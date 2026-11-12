package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"gomelsec/device"
)

// Header3EConfig は 3E/4E フレームのルーティング設定です。
type Header3EConfig struct {
	NetworkNumber      byte
	PCNumber           byte
	DestinationUnit    uint16
	DestinationStation byte
	CPUTimer           uint16
}

// DefaultHeader3EConfig は一般的な標準ルーティング設定を返します。
func DefaultHeader3EConfig() Header3EConfig {
	return Header3EConfig{
		NetworkNumber:      0x00,
		PCNumber:           0xFF,
		DestinationUnit:    0x03FF,
		DestinationStation: 0x00,
		CPUTimer:           0x0010, // 250ms * 16 = 4秒
	}
}

// Framer3E は 3E フレームのパケット処理を行います。
type Framer3E struct {
	cfg Header3EConfig
}

// NewFramer3E は新しい 3E Framer を生成します。
func NewFramer3E(cfg Header3EConfig) *Framer3E {
	return &Framer3E{cfg: cfg}
}

// buildPacket は 3E フレームヘッダとコマンド・ペイロードを結合してパケットを生成します。
func (f *Framer3E) buildPacket(cmd, subCmd uint16, payload []byte) []byte {
	// 要求データ長 = CPU監視タイマ(2B) + コマンド(2B) + サブコマンド(2B) + ペイロード長
	reqDataLen := uint16(2 + 2 + 2 + len(payload))

	totalLen := 2 + 1 + 1 + 2 + 1 + 2 + int(reqDataLen)
	packet := make([]byte, totalLen)

	// サブヘッダ (0x5000)
	binary.LittleEndian.PutUint16(packet[0:2], SubHeader3ERequest)
	// ルーティング部
	packet[2] = f.cfg.NetworkNumber
	packet[3] = f.cfg.PCNumber
	binary.LittleEndian.PutUint16(packet[4:6], f.cfg.DestinationUnit)
	packet[6] = f.cfg.DestinationStation
	// 要求データ長
	binary.LittleEndian.PutUint16(packet[7:9], reqDataLen)
	// CPU監視タイマ
	binary.LittleEndian.PutUint16(packet[9:11], f.cfg.CPUTimer)
	// コマンド & サブコマンド
	binary.LittleEndian.PutUint16(packet[11:13], cmd)
	binary.LittleEndian.PutUint16(packet[13:15], subCmd)

	// ペイロード
	copy(packet[15:], payload)
	return packet
}

func (f *Framer3E) BuildBatchRead(dev device.Device, count uint16, isBit bool) ([]byte, error) {
	code, err := dev.BinaryCode3E()
	if err != nil {
		return nil, err
	}
	subCmd := SubCmdWord
	if isBit {
		subCmd = SubCmdBit
	}

	payload := make([]byte, 6)
	// アドレス (3バイト, リトルエンディアン)
	payload[0] = byte(dev.Number & 0xFF)
	payload[1] = byte((dev.Number >> 8) & 0xFF)
	payload[2] = byte((dev.Number >> 16) & 0xFF)
	// デバイスコード (1バイト)
	payload[3] = code
	// 点数 (2バイト)
	binary.LittleEndian.PutUint16(payload[4:6], count)

	return f.buildPacket(CmdBatchRead, subCmd, payload), nil
}

func (f *Framer3E) BuildBatchWrite(dev device.Device, data []byte, isBit bool) ([]byte, error) {
	code, err := dev.BinaryCode3E()
	if err != nil {
		return nil, err
	}
	subCmd := SubCmdWord
	var count uint16
	if isBit {
		subCmd = SubCmdBit
		// ビット書込み時は 1バイトあたり2ビット(各ニブル)詰め
		// 引数の data の各バイトは 0x00 または 0x01 を想定し、ニブル詰めを行う
		nibblePacked := packBitsToNibbles(data)
		count = uint16(len(data))
		payload := make([]byte, 6+len(nibblePacked))
		payload[0] = byte(dev.Number & 0xFF)
		payload[1] = byte((dev.Number >> 8) & 0xFF)
		payload[2] = byte((dev.Number >> 16) & 0xFF)
		payload[3] = code
		binary.LittleEndian.PutUint16(payload[4:6], count)
		copy(payload[6:], nibblePacked)
		return f.buildPacket(CmdBatchWrite, subCmd, payload), nil
	}

	// ワード書込み
	count = uint16(len(data) / 2)
	payload := make([]byte, 6+len(data))
	payload[0] = byte(dev.Number & 0xFF)
	payload[1] = byte((dev.Number >> 8) & 0xFF)
	payload[2] = byte((dev.Number >> 16) & 0xFF)
	payload[3] = code
	binary.LittleEndian.PutUint16(payload[4:6], count)
	copy(payload[6:], data)

	return f.buildPacket(CmdBatchWrite, subCmd, payload), nil
}

func (f *Framer3E) BuildRandomRead(wordDevs []device.Device, dwordDevs []device.Device) ([]byte, error) {
	wCount := len(wordDevs)
	dwCount := len(dwordDevs)
	if wCount > 255 || dwCount > 255 {
		return nil, errors.New("exceeded maximum devices for random read (max 255)")
	}

	payloadLen := 2 + (wCount * 4) + (dwCount * 4)
	payload := make([]byte, payloadLen)
	payload[0] = byte(wCount)
	payload[1] = byte(dwCount)

	offset := 2
	for _, dev := range wordDevs {
		code, err := dev.BinaryCode3E()
		if err != nil {
			return nil, err
		}
		payload[offset] = byte(dev.Number & 0xFF)
		payload[offset+1] = byte((dev.Number >> 8) & 0xFF)
		payload[offset+2] = byte((dev.Number >> 16) & 0xFF)
		payload[offset+3] = code
		offset += 4
	}
	for _, dev := range dwordDevs {
		code, err := dev.BinaryCode3E()
		if err != nil {
			return nil, err
		}
		payload[offset] = byte(dev.Number & 0xFF)
		payload[offset+1] = byte((dev.Number >> 8) & 0xFF)
		payload[offset+2] = byte((dev.Number >> 16) & 0xFF)
		payload[offset+3] = code
		offset += 4
	}

	return f.buildPacket(CmdRandomRead, SubCmdWord, payload), nil
}

func (f *Framer3E) BuildRandomWriteWords(wordDevs []device.Device, wordVals []uint16, dwordDevs []device.Device, dwordVals []uint32) ([]byte, error) {
	if len(wordDevs) != len(wordVals) || len(dwordDevs) != len(dwordVals) {
		return nil, errors.New("devices and values length mismatch")
	}
	wCount := len(wordDevs)
	dwCount := len(dwordDevs)

	payloadLen := 2 + (wCount * 6) + (dwCount * 8)
	payload := make([]byte, payloadLen)
	payload[0] = byte(wCount)
	payload[1] = byte(dwCount)

	offset := 2
	for i, dev := range wordDevs {
		code, err := dev.BinaryCode3E()
		if err != nil {
			return nil, err
		}
		payload[offset] = byte(dev.Number & 0xFF)
		payload[offset+1] = byte((dev.Number >> 8) & 0xFF)
		payload[offset+2] = byte((dev.Number >> 16) & 0xFF)
		payload[offset+3] = code
		binary.LittleEndian.PutUint16(payload[offset+4:offset+6], wordVals[i])
		offset += 6
	}
	for i, dev := range dwordDevs {
		code, err := dev.BinaryCode3E()
		if err != nil {
			return nil, err
		}
		payload[offset] = byte(dev.Number & 0xFF)
		payload[offset+1] = byte((dev.Number >> 8) & 0xFF)
		payload[offset+2] = byte((dev.Number >> 16) & 0xFF)
		payload[offset+3] = code
		binary.LittleEndian.PutUint32(payload[offset+4:offset+8], dwordVals[i])
		offset += 8
	}

	return f.buildPacket(CmdRandomWrite, SubCmdWord, payload), nil
}

func (f *Framer3E) BuildRandomWriteBits(bitDevs []device.Device, bitVals []bool) ([]byte, error) {
	if len(bitDevs) != len(bitVals) {
		return nil, errors.New("devices and values length mismatch")
	}
	count := len(bitDevs)
	payloadLen := 1 + (count * 5)
	payload := make([]byte, payloadLen)
	payload[0] = byte(count)

	offset := 1
	for i, dev := range bitDevs {
		code, err := dev.BinaryCode3E()
		if err != nil {
			return nil, err
		}
		payload[offset] = byte(dev.Number & 0xFF)
		payload[offset+1] = byte((dev.Number >> 8) & 0xFF)
		payload[offset+2] = byte((dev.Number >> 16) & 0xFF)
		payload[offset+3] = code
		if bitVals[i] {
			payload[offset+4] = 0x01
		} else {
			payload[offset+4] = 0x00
		}
		offset += 5
	}

	return f.buildPacket(CmdRandomWrite, SubCmdBit, payload), nil
}

func (f *Framer3E) BuildLoopback(echoData []byte) ([]byte, error) {
	length := len(echoData)
	if length < 1 || length > 960 {
		return nil, fmt.Errorf("loopback echo data length must be 1..960, got %d", length)
	}
	payload := make([]byte, 2+length)
	binary.LittleEndian.PutUint16(payload[0:2], uint16(length))
	copy(payload[2:], echoData)

	return f.buildPacket(CmdLoopback, SubCmdWord, payload), nil
}

func (f *Framer3E) BuildRawCommand(command uint16, subCommand uint16, reqData []byte) ([]byte, error) {
	return f.buildPacket(command, subCommand, reqData), nil
}

func (f *Framer3E) ParseResponse(reqBytes, respBytes []byte) ([]byte, error) {
	// 3Eフレーム レスポンス最小長 = 2(サブヘッダ) + 5(NW/PC/Unit/局番) + 2(データ長) + 2(終了コード) = 11バイト
	if len(respBytes) < 11 {
		return nil, ErrResponseTooShort
	}

	actualSubHeader := binary.LittleEndian.Uint16(respBytes[0:2])
	if actualSubHeader != SubHeader3EResponse {
		return nil, fmt.Errorf("%w: expected 0xD000, got 0x%04X", ErrInvalidSubHeader, actualSubHeader)
	}

	respDataLen := binary.LittleEndian.Uint16(respBytes[7:9])
	if int(respDataLen) > len(respBytes)-9 {
		return nil, fmt.Errorf("%w: stated %d bytes, but received %d", ErrResponseTooShort, respDataLen, len(respBytes)-9)
	}

	endCode := binary.LittleEndian.Uint16(respBytes[9:11])
	if endCode != 0x0000 {
		desc := PLCErrorDescription(endCode)
		return nil, fmt.Errorf("%w: 0x%04X (%s)", ErrPLCErrorResponse, endCode, desc)
	}

	// 正常完了：データ部抽出 (11バイト目以降)
	payload := respBytes[11 : 9+respDataLen]
	return payload, nil
}

// packBitsToNibbles は各バイトが 0/1 のビット列を 1バイトあたり2ビット(上位ニブル・下位ニブル)にパックします。
func packBitsToNibbles(bits []byte) []byte {
	outLen := (len(bits) + 1) / 2
	out := make([]byte, outLen)
	for i := 0; i < len(bits); i++ {
		byteIdx := i / 2
		val := bits[i] & 0x01
		if i%2 == 0 {
			out[byteIdx] |= (val << 4) // 奇数番目(0スタートでは偶数)は上位ニブル
		} else {
			out[byteIdx] |= val // 偶数番目は下位ニブル
		}
	}
	return out
}
