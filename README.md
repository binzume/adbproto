# ADB protocol implementation for Go

GoでAndroidのADBに接続するためのパッケージです．
[chrome-watch](https://github.com/binzume/chrome-watch)のために作ったものです．

- PC上の `adb-server` を経由せずに直接Androidデバイス上の `adbd` と通信するためのものです
- platform-toolsには依存しないので，単体でAndroidデバイスを操作するアプリケーションを作れます
- プロトコルの実装のみで，USBなどの実装は含んでいません．サンプルではTCPIPで待ち受けている adbd に接続しています

## Usage

cmds/shell が `adb shell` のような動作をするサンプルです．
