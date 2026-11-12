package device

import (
	"errors"
	"fmt"
)

// DeviceType はPLCデバイスの種類を表す列挙型です。
type DeviceType int

const (
	// ビットデバイス
	DevX  DeviceType = iota // 入力 (16進)
	DevY                   // 出力 (16進)
	DevM                   // 内部リレー (10進)
	DevL                   // ラッチリレー (10進)
	DevF                   // アナンシエータ (10進)
	DevV                   // エッジリレー (10進)
	DevB                   // リンクリレー (16進)
	DevS                   // ステップリレー (10進, FX特有/SFC)
	DevSM                  // 特殊リレー (10進)
	DevSB                  // 特殊リンクリレー (16進)
	DevDX                  // ダイレクト入力 (16進)
	DevDY                  // ダイレクト出力 (16進)
	DevTS                  // タイマ接点 (10進)
	DevTC                  // タイマコイル (10進)
	DevCS                  // カウンタ接点 (10進)
	DevCC                  // カウンタコイル (10進)

	// ワードデバイス
	DevD  // データレジスタ (10進)
	DevW  // リンクレジスタ (16進)
	DevTN // タイマ現在値 (10進)
	DevCN // カウンタ現在値 (10進)
	DevSD // 特殊レジスタ (10進)
	DevSW // 特殊リンクレジスタ (16進)
	DevR  // ファイルレジスタ (10進)
	DevZR // ファイルレジスタ連番 (16進/10進)
)

var (
	ErrUnsupportedDevice = errors.New("unsupported device for this frame/series")
	ErrInvalidAddress    = errors.New("invalid device address")
)

// Device は解析済みの単一デバイス表現です。
type Device struct {
	Type   DeviceType // デバイス種別 (DevD, DevM, etc.)
	Name   string     // デバイス名文字 ("D", "M", "X", etc.)
	Number uint32     // アドレス番号 (D100 -> 100, X10 -> 0x10)
	IsBit  bool       // ビットデバイスか
	IsHex  bool       // 16進アドレス体系か
}

// String は人間が読めるデバイス文字列表現を返します。
func (d Device) String() string {
	if d.IsHex {
		return fmt.Sprintf("%s%X", d.Name, d.Number)
	}
	return fmt.Sprintf("%s%d", d.Name, d.Number)
}

// BinaryCode3E は 3E/4E フレーム（Q/L/iQ-R/iQ-F）で使用する1バイトのデバイスコードを返します。
func (d Device) BinaryCode3E() (byte, error) {
	switch d.Type {
	case DevD:
		return 0xA8, nil
	case DevM:
		return 0x90, nil
	case DevSM:
		return 0x91, nil
	case DevSD:
		return 0xA9, nil
	case DevX:
		return 0x9C, nil
	case DevY:
		return 0x9D, nil
	case DevL:
		return 0x92, nil
	case DevF:
		return 0x93, nil
	case DevV:
		return 0x94, nil
	case DevB:
		return 0xA0, nil
	case DevW:
		return 0xB4, nil
	case DevS:
		return 0x98, nil
	case DevTS:
		return 0xC1, nil
	case DevTC:
		return 0xC0, nil
	case DevTN:
		return 0xC2, nil
	case DevCS:
		return 0xC4, nil
	case DevCC:
		return 0xC3, nil
	case DevCN:
		return 0xC5, nil
	case DevSB:
		return 0xA1, nil
	case DevSW:
		return 0xB5, nil
	case DevDX:
		return 0xA2, nil
	case DevDY:
		return 0xA3, nil
	case DevZR:
		return 0xB0, nil
	case DevR:
		return 0xAF, nil
	default:
		return 0x00, fmt.Errorf("%w: %s", ErrUnsupportedDevice, d.Name)
	}
}

// BinaryCode1E は 1E フレーム（A互換/FX3）で使用する1バイトのデバイスコードを返します。
func (d Device) BinaryCode1E() (byte, error) {
	switch d.Type {
	case DevX:
		return 0x58, nil // 'X'
	case DevY:
		return 0x59, nil // 'Y'
	case DevM:
		return 0x4D, nil // 'M'
	case DevS:
		return 0x53, nil // 'S'
	case DevF:
		return 0x46, nil // 'F'
	case DevB:
		return 0x42, nil // 'B'
	case DevD:
		return 0x44, nil // 'D'
	case DevR:
		return 0x52, nil // 'R'
	case DevW:
		return 0x57, nil // 'W'
	case DevTS, DevTC, DevTN:
		return 0x54, nil // 'T' (1Eではコマンド種別で接点/現在値を判定)
	case DevCS, DevCC, DevCN:
		return 0x43, nil // 'C' (1Eではコマンド種別で接点/現在値を判定)
	default:
		return 0x00, fmt.Errorf("%w: %s in 1E frame", ErrUnsupportedDevice, d.Name)
	}
}
