package transport

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotConnected    = errors.New("not connected to plc")
	ErrAlreadyClosed   = errors.New("connection already closed")
	ErrTimeout         = errors.New("communication timeout")
	ErrConnectionReset = errors.New("connection reset by peer")
)

// Transport は下位の物理通信層（TCP / UDP）を抽象化するインターフェースです。
type Transport interface {
	// Connect はPLCへのソケット接続を確立します。
	Connect(ctx context.Context) error

	// Close はソケット接続を閉じます。
	Close() error

	// IsConnected は現在ソケットが有効に接続されているかを返します。
	IsConnected() bool

	// RoundTrip はリクエストバイト列を送信し、PLCからの応答バイト列を受信して返却します。
	RoundTrip(ctx context.Context, req []byte) ([]byte, error)

	// RemoteAddr は接続先のアドレス文字列を返します。
	RemoteAddr() string
}

// Config はトランスポート層の設定です。
type Config struct {
	Host           string
	Port           int
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
}

// DefaultConfig は標準設定を返します。
func DefaultConfig(host string, port int) Config {
	return Config{
		Host:           host,
		Port:           port,
		ConnectTimeout: 3 * time.Second,
		ReadTimeout:    2 * time.Second,
		WriteTimeout:   2 * time.Second,
	}
}
