package gomelsec

import (
	"log/slog"
	"time"
)

// TransportType はトランスポート層プロトコルの種別です。
type TransportType string

const (
	TransportTCP TransportType = "tcp"
	TransportUDP TransportType = "udp"
)

// FrameType はMCプロトコルのフレーム種別です。
type FrameType string

const (
	FrameType1E FrameType = "1E" // A互換フレーム (FX3U等)
	FrameType3E FrameType = "3E" // Q/L/FX5U/iQ-R標準フレーム (推奨)
	FrameType4E FrameType = "4E" // シリアル番号付き拡張フレーム
)

// PLCSeries は対象とするPLCのシリーズ種別です。
type PLCSeries string

const (
	PLCSeriesQ   PLCSeries = "Q"   // Q/L/QnAシリーズ
	PLCSeriesIQR PLCSeries = "IQR" // MELSEC iQ-Rシリーズ
	PLCSeriesIQF PLCSeries = "IQF" // MELSEC iQ-F (FX5U/FX5UJ) シリーズ
	PLCSeriesFX  PLCSeries = "FX"  // FX3U/FX3Gシリーズ
)

// RetryConfig は通信エラー時のリトライ設定です。
type RetryConfig struct {
	// MaxRetries は最大リトライ試行回数です（0でリトライ無効）。
	MaxRetries int
	// InitialInterval は最初のリトライ待機時間です。
	InitialInterval time.Duration
	// MaxInterval はリトライ待機時間の上限です。
	MaxInterval time.Duration
	// Multiplier は指数バックオフの乗数です（例: 1.5 または 2.0）。
	Multiplier float64
	// RetryOnWrite は書込み系操作でもリトライを許可するかどうかです。
	RetryOnWrite bool
}

// DefaultRetryConfig は標準的なリトライ設定を返します。
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:      3,
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		RetryOnWrite:    false,
	}
}

// Config は GoMelsec クライアントの包括的な設定です。
type Config struct {
	// 接続設定
	Host      string
	Port      int
	Transport TransportType
	Frame     FrameType
	PLCSeries PLCSeries

	// ロギング設定 (運用・障害診断用)
	Logger     *slog.Logger // 構造化ロガー (nilの場合はログ出力なし)
	DumpPacket bool         // 送受信パケットの16進ダンプをDebugレベルで出力するか

	// タイムアウト設定
	ConnectTimeout time.Duration
	Timeout        time.Duration

	// 自動再接続設定
	AutoReconnect bool

	// リトライ設定
	Retry RetryConfig

	// ヘルスチェック (死活監視) 設定
	EnableHealthCheck        bool
	HealthCheckInterval      time.Duration
	HealthCheckTimeout       time.Duration
	HealthCheckFailThreshold int
	HealthCheckDevice1E      string // 1Eフレーム時の監視対象デバイス (デフォルト: "D0")

	// 接続状態イベントフック
	OnConnect      func()
	OnDisconnect   func(err error)
	OnHealthChange func(healthy bool, latency time.Duration)

	// 3E/4E 固有ルーティング設定
	NetworkNumber      byte
	PCNumber           byte
	DestinationUnit    uint16
	DestinationStation byte
	CPUTimer           uint16
}

// DefaultConfig は標準的なクライアント初期設定を返します。
func DefaultConfig(host string, port int) Config {
	return Config{
		Host:                     host,
		Port:                     port,
		Transport:                TransportTCP,
		Frame:                    FrameType3E,
		PLCSeries:                PLCSeriesQ,
		ConnectTimeout:           3 * time.Second,
		Timeout:                  2 * time.Second,
		AutoReconnect:            true,
		Retry:                    DefaultRetryConfig(),
		EnableHealthCheck:        false,
		HealthCheckInterval:      5 * time.Second,
		HealthCheckTimeout:       1 * time.Second,
		HealthCheckFailThreshold: 2,
		HealthCheckDevice1E:      "D0",
		NetworkNumber:            0x00,
		PCNumber:                 0xFF,
		DestinationUnit:          0x03FF,
		DestinationStation:       0x00,
		CPUTimer:                 0x0010,
	}
}
