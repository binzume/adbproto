// Simple ADB client
package adbproto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// https://android.googlesource.com/platform/packages/modules/adb/+/master/protocol.txt
const (
	A_SYNC = 0x434e5953
	A_CNXN = 0x4e584e43
	A_AUTH = 0x48545541
	A_OPEN = 0x4e45504f
	A_OKAY = 0x59414b4f
	A_CLSE = 0x45534c43
	A_WRTE = 0x45545257
	A_STLS = 0x534C5453

	A_STLS_VERSION_MIN = 0x01000000
	A_STLS_VERSION     = 0x01000000
)

type PackerHeader struct {
	Command    uint32
	Arg0       uint32
	Arg1       uint32
	DataLength uint32
	DataSum    uint32 // NOTE: data_crc32 is not CRC32...
	Magic      uint32
}

type Packet struct {
	PackerHeader
	Data []byte
}

func NewPacket(cmd, arg0, arg1 uint32, data []byte) *Packet {
	p := &Packet{
		PackerHeader: PackerHeader{
			Command: cmd,
			Arg0:    arg0,
			Arg1:    arg1,
		},
		Data: data,
	}
	p.DataLength = uint32(len(p.Data))
	p.Magic = 0xffffffff ^ p.Command
	p.DataSum = p.sum()
	return p
}

func (p *Packet) sum() (sum uint32) {
	for _, b := range p.Data {
		sum += uint32(b)
	}
	return
}

func (p *Packet) IsValid() bool {
	if p.DataLength != uint32(len(p.Data)) {
		return false
	}
	if p.Magic != 0xffffffff^p.Command {
		return false
	}
	if p.DataSum != p.sum() {
		return false
	}
	return true
}

func (p *Packet) WriteTo(w io.Writer) (int64, error) {
	if err := binary.Write(w, binary.LittleEndian, &p.PackerHeader); err != nil {
		return 0, err
	}
	n, err := w.Write(p.Data)
	return int64(n) + 48, err
}

func (p *Packet) ReadFrom(r io.Reader) (int64, error) {
	if err := binary.Read(r, binary.LittleEndian, &p.PackerHeader); err != nil {
		return 0, err
	}
	p.Data = make([]byte, p.DataLength)
	n, err := io.ReadFull(r, p.Data)
	return int64(n) + 48, err
}

type Conn struct {
	c         io.ReadWriter
	streams   map[uint32]*Stream
	streamSeq uint32
	sendCh    chan<- *Packet
	locker    sync.RWMutex
	closed    bool
	done      chan struct{}
}

func Connect(rw io.ReadWriter, key *rsa.PrivateKey) (*Conn, error) {

	sendCh := make(chan *Packet, 16)
	c := &Conn{streams: map[uint32]*Stream{}, c: rw, sendCh: sendCh, done: make(chan struct{})}
	NewPacket(A_CNXN, 0x01000000, 256*1024, []byte("host::\x00")).WriteTo(c.c)
	p, _ := c.readPacket()
	if p.Command == A_STLS {
		NewPacket(A_STLS, A_STLS_VERSION, 0, nil).WriteTo(c.c)
		if nc, ok := rw.(net.Conn); ok {
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
			if err != nil {
				return nil, err
			}
			config := &tls.Config{
				InsecureSkipVerify: true,
				GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
				},
			}
			tlsconn := tls.Client(nc, config)
			err = tlsconn.Handshake()
			if err != nil {
				return nil, err
			}
			c.c = tlsconn
			p, err = c.readPacket()
			if err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("TLS connection is not supported.")
		}
	}
	if p.Command == A_AUTH {
		if key == nil {
			key, _ = rsa.GenerateKey(rand.Reader, 2048) // generate temporary key.
		} else {
			sign, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, p.Data)
			if err != nil {
				return nil, err
			}
			NewPacket(A_AUTH, 2, 0, sign).WriteTo(c.c)
			p, _ = c.readPacket()
		}
		if p.Command == A_AUTH {
			pkey, _ := ssh.NewPublicKey(&key.PublicKey)
			pubKey := ssh.MarshalAuthorizedKey(pkey)
			NewPacket(A_AUTH, 3, 0, pubKey).WriteTo(c.c)
			p, _ = c.readPacket()
		}
	}
	if p.Command != A_CNXN {
		return nil, fmt.Errorf("invalid response. %v", p)
	}
	go func() {
		for {
			p, err := c.readPacket()
			if err != nil {
				break
			} else if p.Command == A_CLSE {
				c.deleteStrem(p.Arg1)
			} else if s := c.getStream(p.Arg1); s != nil {
				if p.Command == A_WRTE && s.remote != 0 {
					s.Ch <- p.Data
					c.Send(NewPacket(A_OKAY, p.Arg1, p.Arg0, nil))
				} else if p.Command == A_OKAY && s.remote == 0 {
					s.remote = p.Arg0
					s.Ch <- p.Data
				}
			}
		}
		c.Close()
	}()
	go func() {
		for p := range sendCh {
			p.WriteTo(c.c)
		}
	}()
	return c, nil
}

func (c *Conn) Send(p *Packet) error {
	select {
	case <-c.done:
		return fmt.Errorf("closed")
	case c.sendCh <- p:
		return nil
	}
}

func (c *Conn) readPacket() (*Packet, error) {
	var p Packet
	_, err := p.ReadFrom(c.c)
	return &p, err
}

func (c *Conn) Close() {
	c.locker.Lock()
	defer c.locker.Unlock()
	if !c.closed {
		close(c.done)
		c.closed = true
	}
	for _, s := range c.streams {
		close(s.Ch)
	}
	c.streams = map[uint32]*Stream{}
}

func (c *Conn) Closed() <-chan struct{} {
	return c.done
}

type Stream struct {
	conn    *Conn
	local   uint32
	remote  uint32
	readBuf []byte
	Ch      chan []byte
}

func (s *Stream) Read(b []byte) (int, error) {
	if len(s.readBuf) == 0 {
		s.readBuf = <-s.Ch
		if s.readBuf == nil {
			return 0, io.EOF
		}
	}
	n := copy(b, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

func (s *Stream) Write(b []byte) (int, error) {
	return len(b), s.conn.Send(NewPacket(A_WRTE, s.local, s.remote, b))
}

func (s *Stream) Close() error {
	if !s.conn.deleteStrem(s.local) {
		return nil // already closed
	}
	return s.conn.Send(NewPacket(A_CLSE, s.local, s.remote, nil))
}

func (c *Conn) newStream() *Stream {
	c.locker.Lock()
	defer c.locker.Unlock()
	c.streamSeq++
	s := &Stream{local: c.streamSeq, conn: c, Ch: make(chan []byte, 8)}
	c.streams[s.local] = s
	return s
}

func (c *Conn) getStream(id uint32) *Stream {
	c.locker.RLock()
	defer c.locker.RUnlock()
	return c.streams[id]
}

func (c *Conn) deleteStrem(id uint32) bool {
	c.locker.Lock()
	defer c.locker.Unlock()
	if s, ok := c.streams[id]; ok {
		delete(c.streams, id)
		close(s.Ch)
		return true
	}
	return false
}

func (c *Conn) Open(path string) (*Stream, error) {
	s := c.newStream()
	if err := c.Send(NewPacket(A_OPEN, s.local, 0, []byte(path))); err != nil {
		c.deleteStrem(s.local)
		return nil, err
	}
	select {
	case <-c.done:
		c.deleteStrem(s.local)
		return nil, fmt.Errorf("Cannot open %s", path)
	case _, ok := <-s.Ch:
		if !ok {
			c.deleteStrem(s.local)
			return nil, fmt.Errorf("Cannot open %s", path)
		}
	}
	return s, nil
}
