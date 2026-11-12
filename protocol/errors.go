package protocol

import "fmt"

// PLCErrorDescription はPLCから返却された終了コードの日本語解説を返します。
func PLCErrorDescription(code uint16) string {
	switch code {
	case 0x0000:
		return "正常終了"
	// 4000番台: デバイス・アドレス関連
	case 0x4000:
		return "指定されたデバイスコードまたはアドレスが存在しないか、範囲外です"
	case 0x4001:
		return "指定されたデバイスの点数がアクセス可能範囲を超えています"
	case 0x4002:
		return "指定されたデバイスは読出/書込が禁止されています"
	case 0x4003:
		return "指定されたブロック数または点数が上限を超えています"

	// C000番台: コマンド・フレーム形式関連
	case 0xC050:
		return "ASCII/バイナリモードの指定がPLC側の設定と一致していません"
	case 0xC051:
		return "リクエストデータ長が指定されたコマンドの必要長を満たしていません"
	case 0xC052:
		return "リクエストデータ長が指定されたコマンドの上限を超えています"
	case 0xC056:
		return "リクエストヘッダ（NW番号/PC番号/ユニット番号）の指定が不正です"
	case 0xC059:
		return "指定されたコマンドまたはサブコマンドはPLCでサポートされていません"
	case 0xC05A:
		return "指定されたコマンドの読出/書込モード指定が不正です"
	case 0xC05B:
		return "CPUが書込禁止（RUN中書込不可など）状態のため書き込めません"
	case 0xC05C:
		return "リクエストパケットのデータ内容に誤りがあります"
	case 0xC061:
		return "要求データ長と実際の受信パケット長が一致しません"

	// その他
	case 0x0055:
		return "相手局との通信がタイムアウトしました"
	default:
		return fmt.Sprintf("未定義のPLCエラーコード (0x%04X)", code)
	}
}
