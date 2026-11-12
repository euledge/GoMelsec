package transport

import (
	"context"
	"fmt"
	"gomelsec/buffer"
	"net"
	"sync"
	"time"
)

// UDPTransport は UDP プロトコルによる通信実装です。
type UDPTransport struct {
	cfg       Config
	conn      net.Conn
	mu        sync.Mutex
	connected bool
}

// NewUDPTransport は新しい UDPTransport を作成します。
func NewUDPTransport(cfg Config) *UDPTransport {
	return &UDPTransport{
		cfg: cfg,
	}
}

func (u *UDPTransport) Connect(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.connected && u.conn != nil {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", u.cfg.Host, u.cfg.Port)
	dialer := net.Dialer{
		Timeout: u.cfg.ConnectTimeout,
	}

	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		u.connected = false
		return fmt.Errorf("udp dial to %s failed: %w", addr, err)
	}

	u.conn = conn
	u.connected = true
	return nil
}

func (u *UDPTransport) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.connected = false
	if u.conn != nil {
		err := u.conn.Close()
		u.conn = nil
		return err
	}
	return nil
}

func (u *UDPTransport) IsConnected() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.connected && u.conn != nil
}

func (u *UDPTransport) RemoteAddr() string {
	return fmt.Sprintf("%s:%d", u.cfg.Host, u.cfg.Port)
}

func (u *UDPTransport) RoundTrip(ctx context.Context, req []byte) ([]byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if !u.connected || u.conn == nil {
		return nil, ErrNotConnected
	}

	// タイムアウト設定
	writeTimeout := u.cfg.WriteTimeout
	if deadline, ok := ctx.Deadline(); ok {
		writeTimeout = time.Until(deadline)
	}
	_ = u.conn.SetWriteDeadline(time.Now().Add(writeTimeout))

	// 送信
	if _, err := u.conn.Write(req); err != nil {
		return nil, fmt.Errorf("udp write error: %w", err)
	}

	// 受信
	readTimeout := u.cfg.ReadTimeout
	if deadline, ok := ctx.Deadline(); ok {
		readTimeout = time.Until(deadline)
	}
	_ = u.conn.SetReadDeadline(time.Now().Add(readTimeout))

	bufPtr := buffer.GlobalPool.Get()
	defer buffer.GlobalPool.Put(bufPtr)

	n, err := u.conn.Read(*bufPtr)
	if err != nil {
		if errorsIsTimeout(err) {
			return nil, fmt.Errorf("%w: udp read timed out", ErrTimeout)
		}
		return nil, fmt.Errorf("udp read error: %w", err)
	}

	resp := make([]byte, n)
	copy(resp, (*bufPtr)[:n])
	return resp, nil
}
