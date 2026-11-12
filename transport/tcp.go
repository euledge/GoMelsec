package transport

import (
	"context"
	"fmt"
	"gomelsec/buffer"
	"io"
	"net"
	"sync"
	"time"
)

// TCPTransport は TCP プロトコルによる通信実装です。
type TCPTransport struct {
	cfg       Config
	conn      net.Conn
	mu        sync.Mutex
	connected bool
}

// NewTCPTransport は新しい TCPTransport を作成します。
func NewTCPTransport(cfg Config) *TCPTransport {
	return &TCPTransport{
		cfg: cfg,
	}
}

func (t *TCPTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.connected && t.conn != nil {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", t.cfg.Host, t.cfg.Port)
	dialer := net.Dialer{
		Timeout: t.cfg.ConnectTimeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.connected = false
		return fmt.Errorf("tcp connect to %s failed: %w", addr, err)
	}

	// TCP KeepAlive の設定
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		_ = tcpConn.SetNoDelay(true) // Nagleアルゴリズム無効化で低遅延化
	}

	t.conn = conn
	t.connected = true
	return nil
}

func (t *TCPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.connected = false
	if t.conn != nil {
		err := t.conn.Close()
		t.conn = nil
		return err
	}
	return nil
}

func (t *TCPTransport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.connected && t.conn != nil
}

func (t *TCPTransport) RemoteAddr() string {
	return fmt.Sprintf("%s:%d", t.cfg.Host, t.cfg.Port)
}

func (t *TCPTransport) RoundTrip(ctx context.Context, req []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.connected || t.conn == nil {
		return nil, ErrNotConnected
	}

	// タイムアウト設定
	writeTimeout := t.cfg.WriteTimeout
	if deadline, ok := ctx.Deadline(); ok {
		writeTimeout = time.Until(deadline)
	}
	_ = t.conn.SetWriteDeadline(time.Now().Add(writeTimeout))

	// リクエスト送信
	if _, err := t.conn.Write(req); err != nil {
		t.connected = false
		_ = t.conn.Close()
		t.conn = nil
		return nil, fmt.Errorf("write error: %w", err)
	}

	// レスポンス受信
	readTimeout := t.cfg.ReadTimeout
	if deadline, ok := ctx.Deadline(); ok {
		readTimeout = time.Until(deadline)
	}
	_ = t.conn.SetReadDeadline(time.Now().Add(readTimeout))

	// バッファプールから一時受信用バッファを取得
	bufPtr := buffer.GlobalPool.Get()
	defer buffer.GlobalPool.Put(bufPtr)

	n, err := t.conn.Read(*bufPtr)
	if err != nil {
		t.connected = false
		_ = t.conn.Close()
		t.conn = nil
		if errorsIsTimeout(err) {
			return nil, fmt.Errorf("%w: read timed out", ErrTimeout)
		}
		if err == io.EOF {
			return nil, fmt.Errorf("%w: connection closed by peer", ErrConnectionReset)
		}
		return nil, fmt.Errorf("read error: %w", err)
	}

	// 呼び出し元が安全に保持できるよう、受信データサイズ分のスライスをコピーして返却
	resp := make([]byte, n)
	copy(resp, (*bufPtr)[:n])
	return resp, nil
}

func errorsIsTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}
