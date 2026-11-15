package protocol

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"gomelsec/device"
	"strconv"
	"strings"
)

// Framer3EAscii は 3E フレーム（ASCIIコード通信モード）のパケット処理を行います。
type Framer3EAscii struct {
	cfg Header3EConfig
}

// NewFramer3EAscii は新しい 3E ASCII Framer を生成します。
func NewFramer3EAscii(cfg Header3EConfig) *Framer3EAscii {
	return &Framer3EAscii{cfg: cfg}
}

// buildPacket は 3E フレームヘッダ(ASCII)とコマンド・ペイロードを結合してパケットを生成します。
func (f *Framer3EAscii) buildPacket(cmd, subCmd uint16, payload string) []byte {
	// 要求データ長 = CPU監視タイマ(4文字) + コマンド(4文字) + サブコマンド(4文字) + ペイロード文字数
	reqDataLen := 4 + 4 + 4 + len(payload)

	var b strings.Builder
	// サブヘッダ (4文字: "5000")
	b.WriteString("5000")
	// ルーティング部 (8文字: NW 2文字 + PC 2文字 + Unit 4文字)
	fmt.Fprintf(&b, "%02X", f.cfg.NetworkNumber)
	fmt.Fprintf(&b, "%02X", f.cfg.PCNumber)
	fmt.Fprintf(&b, "%04X", f.cfg.DestinationUnit)
	// 要求データ長 (4文字)
	fmt.Fprintf(&b, "%04X", reqDataLen)
	// CPU監視タイマ (4文字)
	fmt.Fprintf(&b, "%04X", f.cfg.CPUTimer)
	// コマンド & サブコマンド (各4文字)
	fmt.Fprintf(&b, "%04X", cmd)
	fmt.Fprintf(&b, "%04X", subCmd)
	// ペイロード
	b.WriteString(payload)

	return []byte(b.String())
}

// formatDeviceAddress はデバイスのアドレスを 6桁の10進数または16進数文字列にフォーマットします。
func formatDeviceAddress(dev device.Device) string {
	if dev.IsHex {
		return fmt.Sprintf("%06X", dev.Number)
	}
	return fmt.Sprintf("%06d", dev.Number)
}

func (f *Framer3EAscii) BuildBatchRead(dev device.Device, count uint16, isBit bool) ([]byte, error) {
	code, err := dev.AsciiCode3E()
	if err != nil {
		return nil, err
	}
	subCmd := SubCmdWord
	if isBit {
		subCmd = SubCmdBit
	}

	payload := fmt.Sprintf("%s%s%04X", code, formatDeviceAddress(dev), count)
	return f.buildPacket(CmdBatchRead, subCmd, payload), nil
}

func (f *Framer3EAscii) BuildBatchWrite(dev device.Device, data []byte, isBit bool) ([]byte, error) {
	code, err := dev.AsciiCode3E()
	if err != nil {
		return nil, err
	}
	subCmd := SubCmdWord
	var count uint16
	var dataStr strings.Builder

	if isBit {
		subCmd = SubCmdBit
		count = uint16(len(data))
		for _, b := range data {
			if b != 0 {
				dataStr.WriteString("1")
			} else {
				dataStr.WriteString("0")
			}
		}
	} else {
		count = uint16(len(data) / 2)
		for i := 0; i < int(count); i++ {
			val := binary.LittleEndian.Uint16(data[i*2 : i*2+2])
			fmt.Fprintf(&dataStr, "%04X", val)
		}
	}

	payload := fmt.Sprintf("%s%s%04X%s", code, formatDeviceAddress(dev), count, dataStr.String())
	return f.buildPacket(CmdBatchWrite, subCmd, payload), nil
}

func (f *Framer3EAscii) BuildRandomRead(wordDevs []device.Device, dwordDevs []device.Device) ([]byte, error) {
	wCount := len(wordDevs)
	if wCount > 255 {
		return nil, errors.New("exceeded maximum devices for random read (max 255)")
	}

	var b strings.Builder
	// ASCII 3E ランダム読出: ワード点数 (4文字: 16進数)
	fmt.Fprintf(&b, "%04X", wCount)
	for _, dev := range wordDevs {
		code, err := dev.AsciiCode3E()
		if err != nil {
			return nil, err
		}
		b.WriteString(code)
		b.WriteString(formatDeviceAddress(dev))
	}

	return f.buildPacket(CmdRandomRead, SubCmdWord, b.String()), nil
}

func (f *Framer3EAscii) BuildRandomWriteWords(wordDevs []device.Device, wordVals []uint16, dwordDevs []device.Device, dwordVals []uint32) ([]byte, error) {
	if len(wordDevs) != len(wordVals) || len(dwordDevs) != len(dwordVals) {
		return nil, errors.New("devices and values length mismatch")
	}
	wCount := len(wordDevs)
	dwCount := len(dwordDevs)
	if wCount > 255 || dwCount > 255 {
		return nil, errors.New("exceeded maximum devices for random write (max 255)")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%02X%02X", wCount, dwCount)
	for i, dev := range wordDevs {
		code, err := dev.AsciiCode3E()
		if err != nil {
			return nil, err
		}
		b.WriteString(code)
		b.WriteString(formatDeviceAddress(dev))
		fmt.Fprintf(&b, "%04X", wordVals[i])
	}
	for i, dev := range dwordDevs {
		code, err := dev.AsciiCode3E()
		if err != nil {
			return nil, err
		}
		b.WriteString(code)
		b.WriteString(formatDeviceAddress(dev))
		fmt.Fprintf(&b, "%08X", dwordVals[i])
	}

	return f.buildPacket(CmdRandomWrite, SubCmdWord, b.String()), nil
}

func (f *Framer3EAscii) BuildRandomWriteBits(bitDevs []device.Device, bitVals []bool) ([]byte, error) {
	if len(bitDevs) != len(bitVals) {
		return nil, errors.New("devices and values length mismatch")
	}
	count := len(bitDevs)
	var b strings.Builder
	fmt.Fprintf(&b, "%02X", count)
	for i, dev := range bitDevs {
		code, err := dev.AsciiCode3E()
		if err != nil {
			return nil, err
		}
		b.WriteString(code)
		b.WriteString(formatDeviceAddress(dev))
		if bitVals[i] {
			b.WriteString("01")
		} else {
			b.WriteString("00")
		}
	}

	return f.buildPacket(CmdRandomWrite, SubCmdBit, b.String()), nil
}

func (f *Framer3EAscii) BuildLoopback(echoData []byte) ([]byte, error) {
	length := len(echoData)
	if length < 1 || length > 960 {
		return nil, fmt.Errorf("loopback echo data length must be 1..960, got %d", length)
	}

	payload := fmt.Sprintf("%04X%s", length, string(echoData))
	return f.buildPacket(CmdLoopback, SubCmdWord, payload), nil
}

func (f *Framer3EAscii) BuildRawCommand(command uint16, subCommand uint16, reqData []byte) ([]byte, error) {
	return f.buildPacket(command, subCommand, string(reqData)), nil
}

func (f *Framer3EAscii) ParseResponse(reqBytes, respBytes []byte) ([]byte, error) {
	respStr := string(respBytes)
	if len(respStr) < 20 {
		return nil, ErrResponseTooShort
	}

	// サブヘッダ "D000" 検証
	if !strings.HasPrefix(strings.ToUpper(respStr), "D000") {
		return nil, fmt.Errorf("%w: expected 'D000', got '%s'", ErrInvalidSubHeader, respStr[:min(4, len(respStr))])
	}

	// ルーティング長とデータ長オフセットの判定
	// 標準5バイトルーティング: "D000" + NW(2) + PC(2) + Unit(4) + Stn(2) = 14文字目からデータ長(4) + 終了コード(4) = 22文字
	// レガシー4バイトルーティング: "D000" + NW(2) + PC(2) + Unit(4) = 12文字目からデータ長(4) + 終了コード(4) = 20文字
	var dataLenOffset, endCodeOffset, payloadOffset int
	isStandard := true

	if len(respStr) >= 22 {
		dlen5, err5 := strconv.ParseUint(respStr[14:18], 16, 32)
		if err5 == nil && 18+int(dlen5) == len(respStr) {
			isStandard = true
		} else if len(respStr) >= 20 {
			dlen4, err4 := strconv.ParseUint(respStr[12:16], 16, 32)
			if err4 == nil && 16+int(dlen4) == len(respStr) {
				isStandard = false
			}
		}
	} else if len(respStr) >= 20 {
		isStandard = false
	}

	if isStandard {
		dataLenOffset = 14
		endCodeOffset = 18
		payloadOffset = 22
	} else {
		dataLenOffset = 12
		endCodeOffset = 16
		payloadOffset = 20
	}

	dataLen, err := strconv.ParseUint(respStr[dataLenOffset:dataLenOffset+4], 16, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid response data length: %w", err)
	}

	minExpected := (dataLenOffset + 4) + int(dataLen)
	if len(respStr) < minExpected {
		return nil, fmt.Errorf("%w: stated %d chars, but received %d", ErrResponseTooShort, dataLen, len(respStr)-(dataLenOffset+4))
	}

	// 終了コードの検証
	endCode, err := strconv.ParseUint(respStr[endCodeOffset:endCodeOffset+4], 16, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid response end code: %w", err)
	}
	if endCode != 0 {
		desc := PLCErrorDescription(uint16(endCode))
		return nil, fmt.Errorf("%w: 0x%04X (%s)", ErrPLCErrorResponse, endCode, desc)
	}

	// ペイロード部の抽出 (終了コード以降)
	payloadStr := respStr[payloadOffset:minExpected]

	// リクエストのコマンド種別を判定
	reqStr := string(reqBytes)
	isLoopback := false
	isBitRead := false

	// リクエストのコマンド/サブコマンドをチェック
	if len(reqStr) >= 30 {
		// リクエストのコマンド位置: "5000" + routing(10) + dataLen(4) + timer(4) = 22文字目から
		cmdOffset := 22
		if !strings.HasPrefix(reqStr[4:], "00") { // ルーティングオフセット確認
			cmdOffset = 22
		}
		if len(reqStr) >= cmdOffset+8 {
			cmdStr := reqStr[cmdOffset : cmdOffset+4]
			subCmdStr := reqStr[cmdOffset+4 : cmdOffset+8]
			if cmdStr == "0619" {
				isLoopback = true
			} else if cmdStr == "0401" && subCmdStr == "0001" {
				isBitRead = true
			}
		}
	}

	if isLoopback {
		// ループバックの場合:
		// エコー文字列の抽出 (二重HEXエンコード等のバリエーションに対応)
		data := []byte(payloadStr)
		if dec1, err := hex.DecodeString(string(data)); err == nil && len(dec1) > 0 {
			data = dec1
			if dec2, err := hex.DecodeString(string(data)); err == nil && len(dec2) > 0 {
				data = dec2
			}
		}
		// 先頭4文字が長さ(例: "000D")の場合はそれをスキップ
		str := string(data)
		if len(str) >= 4 && strings.HasPrefix(str, "00") {
			str = str[4:]
		}
		return []byte(str), nil
	}

	if isBitRead {
		// ビット読出: 各文字が '0' または '1'
		// 上位 API (BatchReadBits) は 1バイトに2点ニブル詰め (0x10 / 0x01) を期待
		nibbles := make([]byte, (len(payloadStr)+1)/2)
		for i, ch := range payloadStr {
			byteIdx := i / 2
			val := byte(0)
			if ch == '1' {
				val = 1
			}
			if i%2 == 0 {
				nibbles[byteIdx] |= (val << 4)
			} else {
				nibbles[byteIdx] |= val
			}
		}
		return nibbles, nil
	}

	// 通常のワード読出またはランダム読出:
	// 各ワードは 4文字の16進数文字列 (例: "0001" -> uint16(1))
	// 上位 API はリトルエンディアンのバイナリバイト列 [0x01, 0x00] を期待
	wordCount := len(payloadStr) / 4
	outBytes := make([]byte, wordCount*2)
	for i := 0; i < wordCount; i++ {
		wStr := payloadStr[i*4 : i*4+4]
		wVal, err := strconv.ParseUint(wStr, 16, 16)
		if err != nil {
			// 16進数パース不可なら生の hex.Decode をフォールバック
			raw, _ := hex.DecodeString(payloadStr)
			return raw, nil
		}
		binary.LittleEndian.PutUint16(outBytes[i*2:i*2+2], uint16(wVal))
	}

	return outBytes, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
