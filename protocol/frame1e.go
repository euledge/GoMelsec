package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"gomelsec/device"
)

// Header1EConfig は 1E フレームの設定です。
type Header1EConfig struct {
	PCNumber byte
	Timer    uint16
}

// DefaultHeader1EConfig は一般的な 1E フレーム設定を返します。
func DefaultHeader1EConfig() Header1EConfig {
	return Header1EConfig{
		PCNumber: 0xFF,
		Timer:    0x0010, // 4秒
	}
}

// Framer1E は 1E フレーム (A互換/FX3) のパケット処理を行います。
type Framer1E struct {
	cfg Header1EConfig
}

// NewFramer1E は新しい 1E Framer を生成します。
func NewFramer1E(cfg Header1EConfig) *Framer1E {
	return &Framer1E{cfg: cfg}
}

func (f *Framer1E) BuildBatchRead(dev device.Device, count uint16, isBit bool) ([]byte, error) {
	code, err := dev.BinaryCode1E()
	if err != nil {
		return nil, err
	}

	subHeader := SubHeader1EWordRead
	if isBit {
		subHeader = SubHeader1EBitRead
	}

	// 1E読出リクエスト長: サブヘッダ(1B) + PC番号(1B) + タイマ(2B) + アドレス(4B) + デバイスコード(2B) + 点数(2B) = 12バイト
	packet := make([]byte, 12)
	packet[0] = subHeader
	packet[1] = f.cfg.PCNumber
	binary.LittleEndian.PutUint16(packet[2:4], f.cfg.Timer)
	binary.LittleEndian.PutUint32(packet[4:8], dev.Number)
	packet[8] = code
	packet[9] = 0x20 // スペース (標準 1E 2バイトコード "D ", "M " 等)
	binary.LittleEndian.PutUint16(packet[10:12], count)

	return packet, nil
}

func (f *Framer1E) BuildBatchWrite(dev device.Device, data []byte, isBit bool) ([]byte, error) {
	code, err := dev.BinaryCode1E()
	if err != nil {
		return nil, err
	}

	subHeader := SubHeader1EWordWrite
	var count uint16
	var payload []byte

	if isBit {
		subHeader = SubHeader1EBitWrite
		// ビット書込み時は各ビットをニブル詰め (1バイト2ビット)
		nibbles := packBitsToNibbles(data)
		count = uint16(len(data))
		payload = nibbles
	} else {
		count = uint16(len(data) / 2)
		payload = data
	}

	totalLen := 12 + len(payload)
	packet := make([]byte, totalLen)
	packet[0] = subHeader
	packet[1] = f.cfg.PCNumber
	binary.LittleEndian.PutUint16(packet[2:4], f.cfg.Timer)
	binary.LittleEndian.PutUint32(packet[4:8], dev.Number)
	packet[8] = code
	packet[9] = 0x20
	binary.LittleEndian.PutUint16(packet[10:12], count)
	copy(packet[12:], payload)

	return packet, nil
}

func (f *Framer1E) BuildRandomRead(wordDevs []device.Device, dwordDevs []device.Device) ([]byte, error) {
	// 1Eフレームには標準的な一括ランダム読出コマンドがないため未サポート
	return nil, fmt.Errorf("%w: random read in 1E frame", ErrUnsupportedOperation)
}

func (f *Framer1E) BuildRandomWriteWords(wordDevs []device.Device, wordVals []uint16, dwordDevs []device.Device, dwordVals []uint32) ([]byte, error) {
	return nil, fmt.Errorf("%w: random write words in 1E frame", ErrUnsupportedOperation)
}

func (f *Framer1E) BuildRandomWriteBits(bitDevs []device.Device, bitVals []bool) ([]byte, error) {
	if len(bitDevs) != len(bitVals) {
		return nil, errors.New("devices and values length mismatch")
	}
	count := len(bitDevs)
	if count > 255 {
		return nil, errors.New("exceeded maximum points for 1E random write (max 255)")
	}

	// 1E ビットランダム書込: サブヘッダ(0x07) + PC(1B) + タイマ(2B) + 点数(1B) + [アドレス(4B)+コード(1B)]*N
	packetLen := 5 + (count * 5)
	packet := make([]byte, packetLen)
	packet[0] = SubHeader1ERandomWrite
	packet[1] = f.cfg.PCNumber
	binary.LittleEndian.PutUint16(packet[2:4], f.cfg.Timer)
	packet[4] = byte(count)

	offset := 5
	for i, dev := range bitDevs {
		code, err := dev.BinaryCode1E()
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(packet[offset:offset+4], dev.Number)
		// 1Eのビットランダム書込ではコードの最上位ビットまたは値フィールドでON/OFFを表現
		// 標準A互換: デバイスコード自体を書き込む
		packet[offset+4] = code
		offset += 5
		_ = bitVals[i]
	}

	return packet, nil
}

func (f *Framer1E) BuildLoopback(echoData []byte) ([]byte, error) {
	// 1Eフレームにはループバックテストコマンドがないため未サポート
	return nil, fmt.Errorf("%w: loopback test in 1E frame", ErrUnsupportedOperation)
}

func (f *Framer1E) BuildRawCommand(command uint16, subCommand uint16, reqData []byte) ([]byte, error) {
	return nil, fmt.Errorf("%w: raw command in 1E frame", ErrUnsupportedOperation)
}

func (f *Framer1E) ParseResponse(reqBytes, respBytes []byte) ([]byte, error) {
	// 1Eフレーム レスポンス最小長 = 2バイト (サブヘッダ + 完了コード)
	if len(respBytes) < 2 {
		if len(respBytes) == 1 && respBytes[0] == SubHeader1EResponseErr {
			return nil, fmt.Errorf("%w: 1E error response", ErrPLCErrorResponse)
		}
		return nil, ErrResponseTooShort
	}

	subHeader := respBytes[0]
	endCode := respBytes[1]

	if subHeader == SubHeader1EResponseErr {
		// 異常終了: 0x5B の後にエラーコード(1バイト)
		return nil, fmt.Errorf("%w: 1E error code 0x%02X", ErrPLCErrorResponse, endCode)
	}

	expectedSubHeader := SubHeader1EResponseOK
	if len(reqBytes) > 0 {
		expectedSubHeader = reqBytes[0] | 0x80
	}

	if subHeader != expectedSubHeader && subHeader != SubHeader1EResponseOK {
		return nil, fmt.Errorf("%w: expected 0x%02X, got 0x%02X", ErrInvalidSubHeader, expectedSubHeader, subHeader)
	}

	// 完了コードのチェック (0x00以外は異常終了)
	if endCode != 0x00 {
		return nil, fmt.Errorf("%w: 1E error code 0x%02X", ErrPLCErrorResponse, endCode)
	}

	// 正常終了: サブヘッダ(1B) + 完了コード(1B: 0x00) の直後以降がデータ部
	payload := respBytes[2:]
	return payload, nil
}
