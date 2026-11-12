package protocol

import (
	"encoding/binary"
	"gomelsec/device"
	"testing"
)

func TestFramer3E_BatchRead(t *testing.T) {
	framer := NewFramer3E(DefaultHeader3EConfig())
	dev, err := device.ParseDevice("D100")
	if err != nil {
		t.Fatal(err)
	}

	packet, err := framer.BuildBatchRead(dev, 10, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// パケット検証:
	// サブヘッダ: 0x5000 (リトルエンディアン: 0x00, 0x50)
	if packet[0] != 0x00 || packet[1] != 0x50 {
		t.Errorf("expected subheader 0x5000, got %02X %02X", packet[0], packet[1])
	}

	// コマンド: 0x0401 (11..13)
	cmd := binary.LittleEndian.Uint16(packet[11:13])
	if cmd != CmdBatchRead {
		t.Errorf("expected command 0x0401, got 0x%04X", cmd)
	}

	// レスポンスパースのテスト (正常応答)
	// レスポンス: [0x00, 0xD0] (0xD000), NW(0), PC(FF), Unit(FF 03), Station(0), DataLen(2+4=6), EndCode(0x0000), Data(12 34 56 78)
	resp := []byte{
		0x00, 0xD0, // サブヘッダ 0xD000
		0x00,       // NW
		0xFF,       // PC
		0xFF, 0x03, // Unit
		0x00,       // Station
		0x06, 0x00, // データ長 = 6バイト (EndCode 2B + Payload 4B)
		0x00, 0x00, // 終了コード = 0x0000 (正常)
		0x12, 0x34, 0x56, 0x78, // ペイロード (4バイト)
	}

	payload, err := framer.ParseResponse(packet, resp)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(payload) != 4 || payload[0] != 0x12 || payload[3] != 0x78 {
		t.Errorf("unexpected payload: %v", payload)
	}
}

func TestFramer3E_Loopback(t *testing.T) {
	framer := NewFramer3E(DefaultHeader3EConfig())
	echo := []byte("MELSEC_PING")

	packet, err := framer.BuildLoopback(echo)
	if err != nil {
		t.Fatal(err)
	}

	// コマンドが 0x0619 であること
	cmd := binary.LittleEndian.Uint16(packet[11:13])
	if cmd != CmdLoopback {
		t.Errorf("expected command 0x0619, got 0x%04X", cmd)
	}
}

func TestFramer4E_Serial(t *testing.T) {
	framer := NewFramer4E(DefaultHeader3EConfig())
	dev, _ := device.ParseDevice("D100")

	// リクエスト1
	req1, err := framer.BuildBatchRead(dev, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	// リクエスト2
	req2, err := framer.BuildBatchRead(dev, 1, false)
	if err != nil {
		t.Fatal(err)
	}

	// 4Eサブヘッダ検証 (0x5400)
	if req1[0] != 0x00 || req1[1] != 0x54 {
		t.Errorf("expected 4E subheader 0x5400, got %02X %02X", req1[0], req1[1])
	}

	serial1 := binary.LittleEndian.Uint16(req1[2:4])
	serial2 := binary.LittleEndian.Uint16(req2[2:4])
	if serial2 != serial1+1 {
		t.Errorf("expected serial to increment, got serial1=%d, serial2=%d", serial1, serial2)
	}

	// 4E レスポンスパース (一致するシリアル)
	resp := []byte{
		0x00, 0xD4, // サブヘッダ 0xD400
		byte(serial1 & 0xFF), byte(serial1 >> 8), // シリアル番号
		0x00, 0x00, // 予約
		0x00, 0xFF, 0xFF, 0x03, 0x00, // NW/PC/Unit/Station
		0x04, 0x00, // データ長 = 4バイト (EndCode 2B + Payload 2B)
		0x00, 0x00, // 終了コード
		0xAB, 0xCD, // ペイロード
	}

	payload, err := framer.ParseResponse(req1, resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(payload) != 2 || payload[0] != 0xAB {
		t.Errorf("unexpected payload: %v", payload)
	}

	// シリアル不一致テスト
	_, err = framer.ParseResponse(req2, resp)
	if err == nil {
		t.Errorf("expected serial mismatch error, got nil")
	}
}

func TestFramer1E_BatchRead(t *testing.T) {
	framer := NewFramer1E(DefaultHeader1EConfig())
	dev, _ := device.ParseDevice("D100")

	packet, err := framer.BuildBatchRead(dev, 5, false)
	if err != nil {
		t.Fatal(err)
	}

	// 1E ワード読出サブヘッダ = 0x01
	if packet[0] != SubHeader1EWordRead {
		t.Errorf("expected 1E word read subheader 0x01, got 0x%02X", packet[0])
	}
	// デバイスコード = 'D' (0x44)
	if packet[8] != 0x44 {
		t.Errorf("expected device code 0x44, got 0x%02X", packet[8])
	}
	// 点数 = 5
	if packet[9] != 5 {
		t.Errorf("expected count 5, got %d", packet[9])
	}

	// レスポンスパース (0x80 + データ)
	respOK := []byte{0x80, 0x11, 0x22, 0x33, 0x44}
	payload, err := framer.ParseResponse(packet, respOK)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if len(payload) != 4 || payload[0] != 0x11 {
		t.Errorf("unexpected payload: %v", payload)
	}

	// エラーレスポンス (0x5B + エラーコード 0x10)
	respErr := []byte{0x5B, 0x10}
	_, err = framer.ParseResponse(packet, respErr)
	if err == nil {
		t.Errorf("expected error, got nil")
	}
}
