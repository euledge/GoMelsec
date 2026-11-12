package transport

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTCPTransport(t *testing.T) {
	// 簡易TCPエコーサーバー起動
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				// 受け取ったデータをそのまま反響
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()

	tcpAddr := listener.Addr().(*net.TCPAddr)
	cfg := Config{
		Host:           "127.0.0.1",
		Port:           tcpAddr.Port,
		ConnectTimeout: 1 * time.Second,
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   1 * time.Second,
	}

	tp := NewTCPTransport(cfg)
	ctx := context.Background()

	// 接続テスト
	if err := tp.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	if !tp.IsConnected() {
		t.Fatalf("expected connected = true")
	}

	// RoundTrip テスト
	reqData := []byte("HELLO_MELSEC")
	respData, err := tp.RoundTrip(ctx, reqData)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	if string(respData) != string(reqData) {
		t.Fatalf("expected %s, got %s", string(reqData), string(respData))
	}

	// 切断テスト
	if err := tp.Close(); err != nil {
		t.Fatalf("failed to close: %v", err)
	}
	if tp.IsConnected() {
		t.Fatalf("expected connected = false")
	}
}

func TestUDPTransport(t *testing.T) {
	// 簡易UDPエコーサーバー起動
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(buf[:n], addr)
		}
	}()

	udpAddr := conn.LocalAddr().(*net.UDPAddr)
	cfg := Config{
		Host:           "127.0.0.1",
		Port:           udpAddr.Port,
		ConnectTimeout: 1 * time.Second,
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   1 * time.Second,
	}

	tp := NewUDPTransport(cfg)
	ctx := context.Background()

	if err := tp.Connect(ctx); err != nil {
		t.Fatalf("failed to connect UDP: %v", err)
	}

	reqData := []byte("HELLO_UDP")
	respData, err := tp.RoundTrip(ctx, reqData)
	if err != nil {
		t.Fatalf("UDP RoundTrip failed: %v", err)
	}
	if string(respData) != string(reqData) {
		t.Fatalf("expected %s, got %s", string(reqData), string(respData))
	}

	_ = tp.Close()
}
