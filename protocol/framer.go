package protocol

import (
	"errors"
	"gomelsec/device"
)

var (
	ErrResponseTooShort     = errors.New("response packet too short")
	ErrInvalidSubHeader     = errors.New("invalid response subheader")
	ErrSerialMismatch       = errors.New("serial number mismatch between request and response")
	ErrPLCErrorResponse     = errors.New("plc error end code")
	ErrUnsupportedOperation = errors.New("operation not supported by this frame")
)

// Framer は 1E/3E/4E フレームのパケット構築と解析を抽象化するインターフェースです。
type Framer interface {
	// BuildBatchRead は一括読出しリクエストパケットを生成します。
	BuildBatchRead(dev device.Device, count uint16, isBit bool) ([]byte, error)

	// BuildBatchWrite は一括書込みリクエストパケットを生成します。
	BuildBatchWrite(dev device.Device, data []byte, isBit bool) ([]byte, error)

	// BuildRandomRead は離散ワード/ダブルワード読出しリクエストパケットを生成します。
	BuildRandomRead(wordDevs []device.Device, dwordDevs []device.Device) ([]byte, error)

	// BuildRandomWriteWords は離散ワード/ダブルワード書込みリクエストパケットを生成します。
	BuildRandomWriteWords(wordDevs []device.Device, wordVals []uint16, dwordDevs []device.Device, dwordVals []uint32) ([]byte, error)

	// BuildRandomWriteBits は離散ビット書込みリクエストパケットを生成します。
	BuildRandomWriteBits(bitDevs []device.Device, bitVals []bool) ([]byte, error)

	// BuildLoopback はループバックテスト用パケットを生成します。
	BuildLoopback(echoData []byte) ([]byte, error)

	// BuildRawCommand は任意のコマンド/サブコマンドを指定したパケットを生成します。
	BuildRawCommand(command uint16, subCommand uint16, reqData []byte) ([]byte, error)

	// ParseResponse は受信パケットを検証し、純粋なデータ部（ペイロード）を抽出して返却します。
	ParseResponse(reqBytes, respBytes []byte) ([]byte, error)
}
