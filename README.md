# ADB protocol implementation for Go

GoでAndroidの[ADB](https://android.googlesource.com/platform/packages/modules/adb/+/master/protocol.txt)に接続するためのパッケージです．
[chrome-watch](https://github.com/binzume/chrome-watch)のために作ったものです．

- PC上の `adb-server` を経由せずに直接Androidデバイス上の `adbd` と通信します
- platform-toolsには依存しないので，単体でAndroidデバイスを操作するアプリケーションを作れます
- プロトコルの実装のみで，USBなどの実装は含んでいません．サンプルではTCPIPで待ち受けている adbd に接続しています
- ADB接続の認証はRSA鍵のみサポートしています．RSA鍵が登録済みであればTLS接続も可能です。

## Usage

T.B.D.

[cmds/shell](cmds/shell/main.go) が `adb shell` のような動作をするサンプルです．

```sh
go run cmds/shell/main.go -t 192.168.0.123:5555
go run cmds/shell/main.go -t 192.168.0.123:5555 shell ls -la /sdcard/
```

## TODO

- File transfer

# License

MIT License
