package gomelsec

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// mockPLCServer は 3E フレームの簡易インメモリPLCサーバーです。
type mockPLCServer struct {
	listener net.Listener
	dMemory  [1000]uint16
	mMemory  [1000]bool
	stopped  bool
}

func startMockPLCServer(t *testing.T) *mockPLCServer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock plc: %v", err)
	}

	server := &mockPLCServer{listener: l}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go server.handleConn(conn)
		}
	}()

	return server
}

func (s *mockPLCServer) handleConn(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF && !s.stopped {
				// closed
			}
			return
		}

		req := buf[:n]
		if len(req) < 15 {
			continue
		}

		// 3Eフレームの解析
		// サブヘッダ 0x5000 (0x00, 0x50)
		cmd := binary.LittleEndian.Uint16(req[11:13])
		subCmd := binary.LittleEndian.Uint16(req[13:15])
		payload := req[15:]

		respPayload := []byte{}

		switch cmd {
		case 0x0619: // ループバック
			// そのままエコーバック
			respPayload = payload

		case 0x0401: // 一括読出し
			addr := int(req[15]) | (int(req[16]) << 8) | (int(req[17]) << 16)
			code := req[18]
			count := int(binary.LittleEndian.Uint16(req[19:21]))

			if subCmd == 0x0000 { // ワード
				if code == 0xA8 { // D
					respPayload = make([]byte, count*2)
					for i := 0; i < count; i++ {
						if addr+i < len(s.dMemory) {
							binary.LittleEndian.PutUint16(respPayload[i*2:i*2+2], s.dMemory[addr+i])
						}
					}
				}
			} else { // ビット (0x0001)
				if code == 0x90 { // M
					// 1バイトに2点ニブル詰め
					respPayload = make([]byte, (count+1)/2)
					for i := 0; i < count; i++ {
						if addr+i < len(s.mMemory) && s.mMemory[addr+i] {
							byteIdx := i / 2
							if i%2 == 0 {
								respPayload[byteIdx] |= 0x10
							} else {
								respPayload[byteIdx] |= 0x01
							}
						}
					}
				}
			}

		case 0x1401: // 一括書込み
			addr := int(req[15]) | (int(req[16]) << 8) | (int(req[17]) << 16)
			code := req[18]
			count := int(binary.LittleEndian.Uint16(req[19:21]))
			data := payload[6:]

			if subCmd == 0x0000 { // ワード
				if code == 0xA8 {
					for i := 0; i < count; i++ {
						if addr+i < len(s.dMemory) && i*2+2 <= len(data) {
							s.dMemory[addr+i] = binary.LittleEndian.Uint16(data[i*2 : i*2+2])
						}
					}
				}
			} else { // ビット
				if code == 0x90 {
					for i := 0; i < count; i++ {
						byteIdx := i / 2
						if byteIdx < len(data) && addr+i < len(s.mMemory) {
							if i%2 == 0 {
								s.mMemory[addr+i] = (data[byteIdx] & 0x10) != 0
							} else {
								s.mMemory[addr+i] = (data[byteIdx] & 0x01) != 0
							}
						}
					}
				}
			}

		case 0x0403: // ランダム読出し
			wCount := int(payload[0])
			dwCount := int(payload[1])
			respPayload = make([]byte, wCount*2+dwCount*4)

			offset := 2
			respOffset := 0
			for i := 0; i < wCount; i++ {
				addr := int(payload[offset]) | (int(payload[offset+1]) << 8) | (int(payload[offset+2]) << 16)
				code := payload[offset+3]
				offset += 4
				if code == 0xA8 && addr < len(s.dMemory) {
					binary.LittleEndian.PutUint16(respPayload[respOffset:respOffset+2], s.dMemory[addr])
				}
				respOffset += 2
			}
			for i := 0; i < dwCount; i++ {
				addr := int(payload[offset]) | (int(payload[offset+1]) << 8) | (int(payload[offset+2]) << 16)
				code := payload[offset+3]
				offset += 4
				if code == 0xA8 && addr+1 < len(s.dMemory) {
					val := uint32(s.dMemory[addr]) | (uint32(s.dMemory[addr+1]) << 16)
					binary.LittleEndian.PutUint32(respPayload[respOffset:respOffset+4], val)
				}
				respOffset += 4
			}

		case 0x1402: // ランダム書込み
			if subCmd == 0x0000 {
				wCount := int(payload[0])
				dwCount := int(payload[1])
				offset := 2
				for i := 0; i < wCount; i++ {
					addr := int(payload[offset]) | (int(payload[offset+1]) << 8) | (int(payload[offset+2]) << 16)
					code := payload[offset+3]
					val := binary.LittleEndian.Uint16(payload[offset+4 : offset+6])
					offset += 6
					if code == 0xA8 && addr < len(s.dMemory) {
						s.dMemory[addr] = val
					}
				}
				for i := 0; i < dwCount; i++ {
					addr := int(payload[offset]) | (int(payload[offset+1]) << 8) | (int(payload[offset+2]) << 16)
					code := payload[offset+3]
					val := binary.LittleEndian.Uint32(payload[offset+4 : offset+8])
					offset += 8
					if code == 0xA8 && addr+1 < len(s.dMemory) {
						s.dMemory[addr] = uint16(val & 0xFFFF)
						s.dMemory[addr+1] = uint16((val >> 16) & 0xFFFF)
					}
				}
			}
		}

		// 3E 正常レスポンスパケット構築
		respLen := uint16(2 + len(respPayload)) // EndCode(2B) + Payload
		resp := make([]byte, 11+len(respPayload))
		binary.LittleEndian.PutUint16(resp[0:2], 0xD000)
		resp[2] = req[2] // NW
		resp[3] = req[3] // PC
		binary.LittleEndian.PutUint16(resp[4:6], binary.LittleEndian.Uint16(req[4:6]))
		resp[6] = req[6]
		binary.LittleEndian.PutUint16(resp[7:9], respLen)
		binary.LittleEndian.PutUint16(resp[9:11], 0x0000) // 正常終了
		copy(resp[11:], respPayload)

		_, _ = conn.Write(resp)
	}
}

func (s *mockPLCServer) Close() {
	s.stopped = true
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func TestClientEndToEnd(t *testing.T) {
	server := startMockPLCServer(t)
	defer server.Close()

	addr := server.listener.Addr().(*net.TCPAddr)
	cfg := DefaultConfig("127.0.0.1", addr.Port)
	cfg.Timeout = 1 * time.Second

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// 1. Connect テスト
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	if !client.IsConnected() {
		t.Fatalf("expected IsConnected = true")
	}

	// 2. Ping / ヘルスチェックテスト (0619H ループバック)
	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
	latency, err := client.PingLatency(ctx)
	if err != nil {
		t.Fatalf("PingLatency failed: %v", err)
	}
	if latency < 0 {
		t.Fatalf("expected non-negative latency, got %v", latency)
	}
	if !client.IsHealthy() {
		t.Fatalf("expected IsHealthy = true")
	}

	// 3. 単一ワード書き込み & 読み出し
	if err := client.WriteWord(ctx, "D10", 12345); err != nil {
		t.Fatalf("WriteWord failed: %v", err)
	}
	val, err := client.ReadWord(ctx, "D10")
	if err != nil {
		t.Fatalf("ReadWord failed: %v", err)
	}
	if val != 12345 {
		t.Fatalf("expected 12345, got %d", val)
	}

	// 4. 単一ビット書き込み & 読み出し
	if err := client.WriteBit(ctx, "M100", true); err != nil {
		t.Fatalf("WriteBit failed: %v", err)
	}
	bitVal, err := client.ReadBit(ctx, "M100")
	if err != nil {
		t.Fatalf("ReadBit failed: %v", err)
	}
	if !bitVal {
		t.Fatalf("expected true, got false")
	}

	// 5. ReadInt32 / WriteInt32 (Long / DINT: 2ワード)
	targetInt32 := int32(305419896) // 0x12345678
	if err := client.WriteInt32(ctx, "D100", targetInt32); err != nil {
		t.Fatalf("WriteInt32 failed: %v", err)
	}
	resInt32, err := client.ReadInt32(ctx, "D100")
	if err != nil {
		t.Fatalf("ReadInt32 failed: %v", err)
	}
	if resInt32 != targetInt32 {
		t.Fatalf("expected %d, got %d", targetInt32, resInt32)
	}

	// 6. ReadFloat32 / WriteFloat32 (REAL: 2ワード)
	targetFloat32 := float32(123.456)
	if err := client.WriteFloat32(ctx, "D200", targetFloat32); err != nil {
		t.Fatalf("WriteFloat32 failed: %v", err)
	}
	resFloat32, err := client.ReadFloat32(ctx, "D200")
	if err != nil {
		t.Fatalf("ReadFloat32 failed: %v", err)
	}
	if fmt.Sprintf("%.3f", resFloat32) != fmt.Sprintf("%.3f", targetFloat32) {
		t.Fatalf("expected %f, got %f", targetFloat32, resFloat32)
	}

	// 7. ReadFloat64 / WriteFloat64 (LREAL / Double: 4ワード)
	targetFloat64 := float64(987654.321098)
	if err := client.WriteFloat64(ctx, "D300", targetFloat64); err != nil {
		t.Fatalf("WriteFloat64 failed: %v", err)
	}
	resFloat64, err := client.ReadFloat64(ctx, "D300")
	if err != nil {
		t.Fatalf("ReadFloat64 failed: %v", err)
	}
	if fmt.Sprintf("%.6f", resFloat64) != fmt.Sprintf("%.6f", targetFloat64) {
		t.Fatalf("expected %f, got %f", targetFloat64, resFloat64)
	}

	// 8. ReadString / WriteString
	targetStr := "HELLO_PLC"
	if err := client.WriteString(ctx, "D400", targetStr); err != nil {
		t.Fatalf("WriteString failed: %v", err)
	}
	resStr, err := client.ReadString(ctx, "D400", len(targetStr))
	if err != nil {
		t.Fatalf("ReadString failed: %v", err)
	}
	if resStr != targetStr {
		t.Fatalf("expected %s, got %s", targetStr, resStr)
	}

	// 9. 生データ (RawBytes / HexString)
	hexData := "A1B2C3D4"
	if err := client.WriteHexString(ctx, "D500", hexData); err != nil {
		t.Fatalf("WriteHexString failed: %v", err)
	}
	resHex, err := client.ReadHexString(ctx, "D500", 2)
	if err != nil {
		t.Fatalf("ReadHexString failed: %v", err)
	}
	if resHex != hexData {
		t.Fatalf("expected %s, got %s", hexData, resHex)
	}

	// 10. ランダム読み出し
	randWords, randDwords, err := client.RandomReadWords(ctx, []string{"D10", "D500"}, []string{"D100"})
	if err != nil {
		t.Fatalf("RandomReadWords failed: %v", err)
	}
	if len(randWords) != 2 || randWords[0] != 12345 {
		t.Fatalf("unexpected randWords: %v", randWords)
	}
	if len(randDwords) != 1 || randDwords[0] != uint32(targetInt32) {
		t.Fatalf("unexpected randDwords: %v", randDwords)
	}
}
