package protocol

import (
	"encoding/binary"
	"fmt"
	"gomelsec/device"
	"sync/atomic"
)

// Framer4E は 4E フレームのパケット処理を行います（シリアル番号によるトランザクション検証付き）。
type Framer4E struct {
	framer3E  *Framer3E
	serialNum atomic.Uint32
}

// NewFramer4E は新しい 4E Framer を生成します。
func NewFramer4E(cfg Header3EConfig) *Framer4E {
	return &Framer4E{
		framer3E: NewFramer3E(cfg),
	}
}

// nextSerial はスレッドセーフに1〜65535のシリアル番号を採番します。
func (f *Framer4E) nextSerial() uint16 {
	val := f.serialNum.Add(1)
	if val > 65535 {
		f.serialNum.Store(1)
		return 1
	}
	return uint16(val)
}

// convertTo4E は 3E フレームパケットを 4E フレームパケットに変換します。
func (f *Framer4E) convertTo4E(packet3E []byte) []byte {
	// 4E = サブヘッダ(2B: 0x5400) + シリアル(2B) + 予約(2B) + 3Eのサブヘッダ以降
	// 全長は 3Eパケット + 4バイト
	serial := f.nextSerial()
	packet4E := make([]byte, len(packet3E)+4)

	binary.BigEndian.PutUint16(packet4E[0:2], SubHeader4ERequest)
	binary.LittleEndian.PutUint16(packet4E[2:4], serial)
	binary.LittleEndian.PutUint16(packet4E[4:6], 0x0000) // 予約

	// 3Eパケットの2バイト目（NW番号）以降をコピー
	copy(packet4E[6:], packet3E[2:])
	return packet4E
}

func (f *Framer4E) BuildBatchRead(dev device.Device, count uint16, isBit bool) ([]byte, error) {
	p3e, err := f.framer3E.BuildBatchRead(dev, count, isBit)
	if err != nil {
		return nil, err
	}
	return f.convertTo4E(p3e), nil
}

func (f *Framer4E) BuildBatchWrite(dev device.Device, data []byte, isBit bool) ([]byte, error) {
	p3e, err := f.framer3E.BuildBatchWrite(dev, data, isBit)
	if err != nil {
		return nil, err
	}
	return f.convertTo4E(p3e), nil
}

func (f *Framer4E) BuildRandomRead(wordDevs []device.Device, dwordDevs []device.Device) ([]byte, error) {
	p3e, err := f.framer3E.BuildRandomRead(wordDevs, dwordDevs)
	if err != nil {
		return nil, err
	}
	return f.convertTo4E(p3e), nil
}

func (f *Framer4E) BuildRandomWriteWords(wordDevs []device.Device, wordVals []uint16, dwordDevs []device.Device, dwordVals []uint32) ([]byte, error) {
	p3e, err := f.framer3E.BuildRandomWriteWords(wordDevs, wordVals, dwordDevs, dwordVals)
	if err != nil {
		return nil, err
	}
	return f.convertTo4E(p3e), nil
}

func (f *Framer4E) BuildRandomWriteBits(bitDevs []device.Device, bitVals []bool) ([]byte, error) {
	p3e, err := f.framer3E.BuildRandomWriteBits(bitDevs, bitVals)
	if err != nil {
		return nil, err
	}
	return f.convertTo4E(p3e), nil
}

func (f *Framer4E) BuildLoopback(echoData []byte) ([]byte, error) {
	p3e, err := f.framer3E.BuildLoopback(echoData)
	if err != nil {
		return nil, err
	}
	return f.convertTo4E(p3e), nil
}

func (f *Framer4E) BuildRawCommand(command uint16, subCommand uint16, reqData []byte) ([]byte, error) {
	p3e, err := f.framer3E.BuildRawCommand(command, subCommand, reqData)
	if err != nil {
		return nil, err
	}
	return f.convertTo4E(p3e), nil
}

func (f *Framer4E) ParseResponse(reqBytes, respBytes []byte) ([]byte, error) {
	// 4Eフレーム レスポンス最小長 = 2(サブヘッダ) + 2(シリアル) + 2(予約) + 5(NW/PC/Unit/局番) + 2(データ長) + 2(終了コード) = 15バイト
	if len(respBytes) < 15 {
		return nil, ErrResponseTooShort
	}

	actualSubHeader := binary.BigEndian.Uint16(respBytes[0:2])
	if actualSubHeader != SubHeader4EResponse {
		return nil, fmt.Errorf("%w: expected 0xD400, got 0x%04X", ErrInvalidSubHeader, actualSubHeader)
	}

	// リクエストのシリアル番号との一致検証
	if len(reqBytes) >= 4 {
		reqSerial := binary.LittleEndian.Uint16(reqBytes[2:4])
		respSerial := binary.LittleEndian.Uint16(respBytes[2:4])
		if reqSerial != respSerial {
			return nil, fmt.Errorf("%w: req=%d, resp=%d", ErrSerialMismatch, reqSerial, respSerial)
		}
	}

	respDataLen := binary.LittleEndian.Uint16(respBytes[11:13])
	if int(respDataLen) > len(respBytes)-13 {
		return nil, fmt.Errorf("%w: stated %d bytes, but received %d", ErrResponseTooShort, respDataLen, len(respBytes)-13)
	}

	endCode := binary.LittleEndian.Uint16(respBytes[13:15])
	if endCode != 0x0000 {
		desc := PLCErrorDescription(endCode)
		return nil, fmt.Errorf("%w: 0x%04X (%s)", ErrPLCErrorResponse, endCode, desc)
	}

	// 正常完了：データ部抽出 (15バイト目以降)
	payload := respBytes[15 : 13+respDataLen]
	return payload, nil
}
