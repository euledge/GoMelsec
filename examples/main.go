package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"gomelsec"
)

func main() {
	// ========================================================
	// 1. 実運用向け構造化ロガーの設定 (JSON形式またはText形式)
	// ========================================================
	// 例: 本番環境のコンテナ/Fluentd/Datadog向けにJSON出力、開発時はTextHandler
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug, // Debugレベルで送受信HEXダンプや再接続の詳細を出力
	})
	logger := slog.New(logHandler)

	// ========================================================
	// 2. クライアント設定 (障害診断・自動復旧オプション)
	// ========================================================
	cfg := gomelsec.Config{
		Host:      "192.168.1.10",
		Port:      5002,
		Transport: gomelsec.TransportTCP,
		Frame:     gomelsec.FrameType3E,
		PLCSeries: gomelsec.PLCSeriesQ,

		// ログ出力設定
		Logger:     logger, // 構造化ロガーを注入
		DumpPacket: true,   // 送受信HEXパケットをDebugログに出力 (Wireshark照合に便利)

		// タイムアウト
		ConnectTimeout: 2 * time.Second,
		Timeout:        1 * time.Second,

		// 障害時の自動再接続 & 指数バックオフリーライ
		AutoReconnect: true,
		Retry: gomelsec.RetryConfig{
			MaxRetries:      3,                      // 最大3回リトライ
			InitialInterval: 100 * time.Millisecond, // 初回100ms
			Multiplier:      2.0,                    // 100ms -> 200ms -> 400ms
			MaxInterval:     1 * time.Second,
			RetryOnWrite:    false,                  // 誤作動防止のため書込みはリトライしない (読出しのみ安全にリトライ)
		},

		// バックグラウンド死活監視 (Keep-Alive / Health Check)
		EnableHealthCheck:        true,
		HealthCheckInterval:      5 * time.Second, // 5秒ごとにループバック(0619H)実行
		HealthCheckTimeout:       1 * time.Second,
		HealthCheckFailThreshold: 2, // 2回連続失敗で切断判定し自動再接続

		// イベント通知フック (監視アラート送信やメトリクス計測に利用)
		OnConnect: func() {
			logger.Info("[EVENT] PLCに接続しました")
		},
		OnDisconnect: func(err error) {
			logger.Error("[EVENT] PLC切断検知 (自動再接続を試行します)", slog.String("error", err.Error()))
		},
		OnHealthChange: func(healthy bool, latency time.Duration) {
			logger.Info("[EVENT] PLC健全性変化",
				slog.Bool("healthy", healthy),
				slog.Duration("rtt", latency),
			)
		},
	}

	client, err := gomelsec.NewClient(cfg)
	if err != nil {
		logger.Error("クライアント生成失敗", slog.String("error", err.Error()))
		return
	}
	defer client.Close()

	ctx := context.Background()

	// 接続実行 (接続失敗時はエラーログが詳細に出力されます)
	if err := client.Connect(ctx); err != nil {
		logger.Error("初回接続失敗 (実機がない場合はスキップ)", slog.String("error", err.Error()))
		return
	}

	// データの読み出し例
	// 万一PLC側で未定義のアドレス（範囲外）を指定した場合、
	// 「0x4000: 指定されたデバイスコードまたはアドレスが存在しないか、範囲外です」
	// といった具体的な日本語解説付きエラーが返ります。
	val, err := client.ReadInt32(ctx, "D100")
	if err != nil {
		logger.Error("D100読み出し失敗", slog.String("error", err.Error()))
	} else {
		fmt.Printf("D100 = %d\n", val)
	}
}
