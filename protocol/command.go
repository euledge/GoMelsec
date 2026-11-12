package protocol

// MCプロトコル コマンド定義 (3E/4Eフレーム用)
const (
	// 一括読出 (Batch Read)
	CmdBatchRead uint16 = 0x0401
	// 一括書込 (Batch Write)
	CmdBatchWrite uint16 = 0x1401

	// ランダム読出 (Random Read)
	CmdRandomRead uint16 = 0x0403
	// ランダム書込 (Random Write)
	CmdRandomWrite uint16 = 0x1402

	// 複数ブロック一括読出 / 書込 (Multi-block Read / Write)
	CmdMultiBlockRead  uint16 = 0x0406
	CmdMultiBlockWrite uint16 = 0x1406

	// ループバックテスト (通信健全性診断)
	CmdLoopback uint16 = 0x0619
)

// サブコマンド定義
const (
	// ワード単位アクセス
	SubCmdWord uint16 = 0x0000
	// ビット単位アクセス
	SubCmdBit uint16 = 0x0001
)

// サブヘッダ定義 (バイナリ通信)
const (
	// 3Eフレーム
	SubHeader3ERequest  uint16 = 0x5000
	SubHeader3EResponse uint16 = 0xD000

	// 4Eフレーム
	SubHeader4ERequest  uint16 = 0x5400
	SubHeader4EResponse uint16 = 0xD400

	// 1Eフレーム (コマンド兼用サブヘッダ)
	SubHeader1EBitRead     byte = 0x00
	SubHeader1EWordRead    byte = 0x01
	SubHeader1EBitWrite    byte = 0x02
	SubHeader1EWordWrite   byte = 0x03
	SubHeader1ERandomWrite byte = 0x07 // ビットランダム書込
	SubHeader1EResponseOK  byte = 0x80
	SubHeader1EResponseErr byte = 0x5B
)
