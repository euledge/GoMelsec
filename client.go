package gomelsec

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"gomelsec/device"
	"gomelsec/protocol"
	"gomelsec/transport"
	"log/slog"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Client はMELSEC通信クライアントの公開インタフェースです。
type Client interface {
	// 接続管理・死活監視
	Connect(ctx context.Context) error
	Close() error
	IsConnected() bool
	Ping(ctx context.Context) error
	PingLatency(ctx context.Context) (time.Duration, error)
	IsHealthy() bool
	LastLatency() time.Duration

	// 単一読み書き
	ReadBit(ctx context.Context, devStr string, opts ...CallOption) (bool, error)
	WriteBit(ctx context.Context, devStr string, value bool, opts ...CallOption) error
	ReadWord(ctx context.Context, devStr string, opts ...CallOption) (uint16, error)
	WriteWord(ctx context.Context, devStr string, value uint16, opts ...CallOption) error

	// 型安全マルチワード読み書き
	ReadInt16(ctx context.Context, devStr string, opts ...CallOption) (int16, error)
	WriteInt16(ctx context.Context, devStr string, value int16, opts ...CallOption) error
	ReadUint16(ctx context.Context, devStr string, opts ...CallOption) (uint16, error)
	WriteUint16(ctx context.Context, devStr string, value uint16, opts ...CallOption) error

	ReadInt32(ctx context.Context, headDev string, opts ...CallOption) (int32, error)
	WriteInt32(ctx context.Context, headDev string, value int32, opts ...CallOption) error
	ReadUint32(ctx context.Context, headDev string, opts ...CallOption) (uint32, error)
	WriteUint32(ctx context.Context, headDev string, value uint32, opts ...CallOption) error

	ReadInt64(ctx context.Context, headDev string, opts ...CallOption) (int64, error)
	WriteInt64(ctx context.Context, headDev string, value int64, opts ...CallOption) error
	ReadUint64(ctx context.Context, headDev string, opts ...CallOption) (uint64, error)
	WriteUint64(ctx context.Context, headDev string, value uint64, opts ...CallOption) error

	ReadFloat32(ctx context.Context, headDev string, opts ...CallOption) (float32, error)
	WriteFloat32(ctx context.Context, headDev string, value float32, opts ...CallOption) error
	ReadFloat64(ctx context.Context, headDev string, opts ...CallOption) (float64, error)
	WriteFloat64(ctx context.Context, headDev string, value float64, opts ...CallOption) error

	ReadString(ctx context.Context, headDev string, lengthInBytes int, opts ...CallOption) (string, error)
	WriteString(ctx context.Context, headDev string, text string, opts ...CallOption) error

	// 一括（ブロック）読み書き
	BatchReadBits(ctx context.Context, headDev string, count uint16, opts ...CallOption) ([]bool, error)
	BatchWriteBits(ctx context.Context, headDev string, values []bool, opts ...CallOption) error
	BatchReadWords(ctx context.Context, headDev string, count uint16, opts ...CallOption) ([]uint16, error)
	BatchWriteWords(ctx context.Context, headDev string, values []uint16, opts ...CallOption) error

	// ランダム読み書き
	RandomReadWords(ctx context.Context, wordDevs []string, dwordDevs []string, opts ...CallOption) (words []uint16, dwords []uint32, err error)
	RandomWriteWords(ctx context.Context, wordDevs []string, wordVals []uint16, dwordDevs []string, dwordVals []uint32, opts ...CallOption) error
	RandomWriteBits(ctx context.Context, bitDevs []string, bitVals []bool, opts ...CallOption) error

	// 生データ / HEX 読み書き & コマンド実行
	ReadRawBytes(ctx context.Context, headDev string, byteLength int, opts ...CallOption) ([]byte, error)
	WriteRawBytes(ctx context.Context, headDev string, data []byte, opts ...CallOption) error
	ReadHexString(ctx context.Context, headDev string, wordCount int, opts ...CallOption) (string, error)
	WriteHexString(ctx context.Context, headDev string, hexStr string, opts ...CallOption) error
	ExecuteCommand(ctx context.Context, command uint16, subCommand uint16, reqData []byte, opts ...CallOption) ([]byte, error)
}

// clientImpl は Client インタフェースの実装構造体です。
type clientImpl struct {
	cfg       Config
	transport transport.Transport
	framer    protocol.Framer
	logger    *slog.Logger

	// 健全性ステータス
	healthy     atomic.Bool
	lastLatency atomic.Int64 // nanoseconds
	failCount   atomic.Int32

	// ライフサイクル
	closeOnce sync.Once
	stopChan  chan struct{}
}

// NewClient は新しい MELSEC クライアントを生成します。
func NewClient(cfg Config) (Client, error) {
	if cfg.Host == "" {
		return nil, errors.New("host cannot be empty")
	}
	if cfg.Port <= 0 {
		return nil, errors.New("port must be positive")
	}

	// トランスポート層の初期化
	tpCfg := transport.Config{
		Host:           cfg.Host,
		Port:           cfg.Port,
		ConnectTimeout: cfg.ConnectTimeout,
		ReadTimeout:    cfg.Timeout,
		WriteTimeout:   cfg.Timeout,
	}

	var tp transport.Transport
	if cfg.Transport == TransportUDP {
		tp = transport.NewUDPTransport(tpCfg)
	} else {
		tp = transport.NewTCPTransport(tpCfg)
	}

	// Framer の初期化
	h3eCfg := protocol.Header3EConfig{
		NetworkNumber:      cfg.NetworkNumber,
		PCNumber:           cfg.PCNumber,
		DestinationUnit:    cfg.DestinationUnit,
		DestinationStation: cfg.DestinationStation,
		CPUTimer:           cfg.CPUTimer,
	}

	var framer protocol.Framer
	if cfg.Format == FormatASCII {
		framer = protocol.NewFramer3EAscii(h3eCfg)
	} else {
		switch cfg.Frame {
		case FrameType1E:
			h1eCfg := protocol.Header1EConfig{
				PCNumber: cfg.PCNumber,
				Timer:    cfg.CPUTimer,
			}
			framer = protocol.NewFramer1E(h1eCfg)
		case FrameType4E:
			framer = protocol.NewFramer4E(h3eCfg)
		default: // FrameType3E
			framer = protocol.NewFramer3E(h3eCfg)
		}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	c := &clientImpl{
		cfg:       cfg,
		transport: tp,
		framer:    framer,
		logger:    logger,
		stopChan:  make(chan struct{}),
	}

	// 自動ヘルスチェックが有効な場合、バックグラウンドゴルーチンを開始
	if cfg.EnableHealthCheck {
		go c.healthCheckLoop()
	}

	return c, nil
}

// NewIQFClient は MELSEC iQ-F (FX5U/FX5UJ) 向けの推奨設定でクライアントを生成するヘルパーです。
func NewIQFClient(host string, port int) (Client, error) {
	cfg := DefaultConfig(host, port)
	cfg.PLCSeries = PLCSeriesIQF
	cfg.Frame = FrameType3E
	cfg.Transport = TransportTCP
	return NewClient(cfg)
}

// NewFX3UClient は FX3U/FX3G (1Eフレーム) 向けの推奨設定でクライアントを生成するヘルパーです。
func NewFX3UClient(host string, port int) (Client, error) {
	cfg := DefaultConfig(host, port)
	cfg.PLCSeries = PLCSeriesFX
	cfg.Frame = FrameType1E
	cfg.Transport = TransportTCP
	return NewClient(cfg)
}

// --- 接続管理 & ヘルスチェック ---

func (c *clientImpl) Connect(ctx context.Context) error {
	c.logger.DebugContext(ctx, "connecting to plc",
		slog.String("host", c.cfg.Host),
		slog.Int("port", c.cfg.Port),
		slog.String("transport", string(c.cfg.Transport)),
		slog.String("frame", string(c.cfg.Frame)),
	)

	err := c.transport.Connect(ctx)
	if err == nil {
		c.healthy.Store(true)
		c.failCount.Store(0)
		c.logger.InfoContext(ctx, "connected to plc successfully",
			slog.String("remote_addr", c.transport.RemoteAddr()),
		)
		if c.cfg.OnConnect != nil {
			c.cfg.OnConnect()
		}
	} else {
		c.logger.ErrorContext(ctx, "failed to connect to plc",
			slog.String("remote_addr", c.transport.RemoteAddr()),
			slog.String("error", err.Error()),
		)
	}
	return err
}

func (c *clientImpl) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.stopChan)
		err = c.transport.Close()
		c.healthy.Store(false)
		c.logger.Info("connection to plc closed",
			slog.String("remote_addr", c.transport.RemoteAddr()),
		)
	})
	return err
}

func (c *clientImpl) IsConnected() bool {
	return c.transport.IsConnected()
}

func (c *clientImpl) IsHealthy() bool {
	return c.healthy.Load()
}

func (c *clientImpl) LastLatency() time.Duration {
	return time.Duration(c.lastLatency.Load())
}

func (c *clientImpl) Ping(ctx context.Context) error {
	_, err := c.PingLatency(ctx)
	return err
}

func (c *clientImpl) PingLatency(ctx context.Context) (time.Duration, error) {
	start := time.Now()

	// 3E/4E の場合はループバックテスト (0619) を実行
	if c.cfg.Frame == FrameType3E || c.cfg.Frame == FrameType4E {
		echo := []byte("GOMELSEC_PING")
		req, err := c.framer.BuildLoopback(echo)
		if err != nil {
			return 0, err
		}
		resp, err := c.execute(ctx, req, false)
		if err != nil {
			return 0, err
		}
		payload, err := c.framer.ParseResponse(req, resp)
		if err != nil {
			return 0, err
		}
		// ループバック応答の検証: [長さ(2B)] + [エコーデータ]
		if len(payload) < 2+len(echo) || string(payload[2:2+len(echo)]) != string(echo) {
			return 0, fmt.Errorf("loopback echo mismatch")
		}
	} else {
		// 1Eフレームの場合は監視デバイス (デフォルト: D0) を1ワード読出し
		target := c.cfg.HealthCheckDevice1E
		if target == "" {
			target = "D0"
		}
		_, err := c.ReadWord(ctx, target)
		if err != nil {
			return 0, err
		}
	}

	latency := time.Since(start)
	c.lastLatency.Store(int64(latency))
	c.healthy.Store(true)
	c.failCount.Store(0)
	return latency, nil
}

func (c *clientImpl) healthCheckLoop() {
	interval := c.cfg.HealthCheckInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	timeout := c.cfg.HealthCheckTimeout
	if timeout <= 0 {
		timeout = 1 * time.Second
	}

	threshold := int32(c.cfg.HealthCheckFailThreshold)
	if threshold <= 0 {
		threshold = 2
	}

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			latency, err := c.PingLatency(ctx)
			cancel()

			if err != nil {
				fails := c.failCount.Add(1)
				c.logger.WarnContext(ctx, "plc health check ping failed",
					slog.Int("consecutive_failures", int(fails)),
					slog.Int("threshold", int(threshold)),
					slog.String("error", err.Error()),
				)
				if fails >= threshold && c.healthy.Load() {
					c.healthy.Store(false)
					c.logger.ErrorContext(ctx, "plc marked unhealthy, threshold exceeded",
						slog.Int("total_failures", int(fails)),
					)
					if c.cfg.OnHealthChange != nil {
						c.cfg.OnHealthChange(false, 0)
					}
					if c.cfg.OnDisconnect != nil {
						c.cfg.OnDisconnect(err)
					}
					// 自動再接続
					if c.cfg.AutoReconnect {
						c.logger.InfoContext(ctx, "triggering auto-reconnect due to health check failure")
						_ = c.transport.Close()
						_ = c.Connect(context.Background())
					}
				}
			} else {
				if !c.healthy.Load() {
					c.healthy.Store(true)
					c.logger.InfoContext(ctx, "plc connection restored to healthy",
						slog.Duration("latency", latency),
					)
					if c.cfg.OnHealthChange != nil {
						c.cfg.OnHealthChange(true, latency)
					}
				}
			}
		}
	}
}

// execute はパケットを送信し、切断時の自動再接続と指数バックオフリートライを処理します。
func (c *clientImpl) execute(ctx context.Context, req []byte, isWrite bool, opts ...CallOption) ([]byte, error) {
	// オプション解決
	var callOpts CallOptions
	for _, opt := range opts {
		opt(&callOpts)
	}

	maxRetries := c.cfg.Retry.MaxRetries
	if callOpts.MaxRetries != nil {
		maxRetries = *callOpts.MaxRetries
	}

	initialInterval := c.cfg.Retry.InitialInterval
	if callOpts.RetryInterval != nil {
		initialInterval = *callOpts.RetryInterval
	}
	if initialInterval <= 0 {
		initialInterval = 100 * time.Millisecond
	}

	multiplier := c.cfg.Retry.Multiplier
	if multiplier <= 1.0 {
		multiplier = 1.5
	}
	maxInterval := c.cfg.Retry.MaxInterval
	if maxInterval <= 0 {
		maxInterval = 2 * time.Second
	}

	// 書込み系でリトライ不可設定の場合
	if isWrite && !c.cfg.Retry.RetryOnWrite && callOpts.MaxRetries == nil {
		maxRetries = 0
	}

	currentInterval := initialInterval
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// コンテキスト確認
		if err := ctx.Err(); err != nil {
			c.logger.ErrorContext(ctx, "request context canceled", slog.String("error", err.Error()))
			return nil, err
		}

		// 未接続なら自動接続
		if !c.transport.IsConnected() {
			c.logger.DebugContext(ctx, "socket not connected, attempting to connect before request")
			if err := c.transport.Connect(ctx); err != nil {
				lastErr = err
				c.logger.WarnContext(ctx, "failed to connect before request",
					slog.Int("attempt", attempt),
					slog.String("error", err.Error()),
				)
				goto RETRY_WAIT
			}
		}

		// ラウンドトリップ実行
		{
			if c.cfg.DumpPacket {
				c.logger.DebugContext(ctx, "sending packet to plc",
					slog.Int("bytes", len(req)),
					slog.String("hex", hex.EncodeToString(req)),
				)
			}

			resp, err := c.transport.RoundTrip(ctx, req)
			if err == nil {
				if c.cfg.DumpPacket {
					c.logger.DebugContext(ctx, "received packet from plc",
						slog.Int("bytes", len(resp)),
						slog.String("hex", hex.EncodeToString(resp)),
					)
				}
				return resp, nil
			}

			lastErr = err
			c.logger.WarnContext(ctx, "communication error during roundtrip",
				slog.Int("attempt", attempt),
				slog.Int("max_retries", maxRetries),
				slog.String("error", err.Error()),
			)

			// 接続断ならソケットを閉じる
			if errors.Is(err, transport.ErrConnectionReset) || errors.Is(err, transport.ErrNotConnected) {
				c.logger.WarnContext(ctx, "connection reset or dropped, closing socket for reconnect")
				_ = c.transport.Close()
			}
		}

	RETRY_WAIT:
		if attempt < maxRetries {
			c.logger.InfoContext(ctx, "waiting before retry",
				slog.Int("next_attempt", attempt+1),
				slog.Duration("interval", currentInterval),
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(currentInterval):
			}
			// 指数バックオフ計算
			nextInterval := time.Duration(float64(currentInterval) * multiplier)
			if nextInterval > maxInterval {
				nextInterval = maxInterval
			}
			currentInterval = nextInterval
		}
	}

	c.logger.ErrorContext(ctx, "request failed permanently after retries",
		slog.Int("total_attempts", maxRetries+1),
		slog.String("last_error", lastErr.Error()),
	)
	return nil, fmt.Errorf("request failed after %d retries: %w", maxRetries, lastErr)
}

// --- 単一読み書き (便利メソッド) ---

func (c *clientImpl) ReadBit(ctx context.Context, devStr string, opts ...CallOption) (bool, error) {
	bits, err := c.BatchReadBits(ctx, devStr, 1, opts...)
	if err != nil {
		return false, err
	}
	if len(bits) == 0 {
		return false, errors.New("empty bit response")
	}
	return bits[0], nil
}

func (c *clientImpl) WriteBit(ctx context.Context, devStr string, value bool, opts ...CallOption) error {
	return c.BatchWriteBits(ctx, devStr, []bool{value}, opts...)
}

func (c *clientImpl) ReadWord(ctx context.Context, devStr string, opts ...CallOption) (uint16, error) {
	words, err := c.BatchReadWords(ctx, devStr, 1, opts...)
	if err != nil {
		return 0, err
	}
	if len(words) == 0 {
		return 0, errors.New("empty word response")
	}
	return words[0], nil
}

func (c *clientImpl) WriteWord(ctx context.Context, devStr string, value uint16, opts ...CallOption) error {
	return c.BatchWriteWords(ctx, devStr, []uint16{value}, opts...)
}

// --- 型安全マルチワード読み書き ---

func (c *clientImpl) ReadInt16(ctx context.Context, devStr string, opts ...CallOption) (int16, error) {
	val, err := c.ReadWord(ctx, devStr, opts...)
	return int16(val), err
}

func (c *clientImpl) WriteInt16(ctx context.Context, devStr string, value int16, opts ...CallOption) error {
	return c.WriteWord(ctx, devStr, uint16(value), opts...)
}

func (c *clientImpl) ReadUint16(ctx context.Context, devStr string, opts ...CallOption) (uint16, error) {
	return c.ReadWord(ctx, devStr, opts...)
}

func (c *clientImpl) WriteUint16(ctx context.Context, devStr string, value uint16, opts ...CallOption) error {
	return c.WriteWord(ctx, devStr, value, opts...)
}

func (c *clientImpl) ReadInt32(ctx context.Context, headDev string, opts ...CallOption) (int32, error) {
	words, err := c.BatchReadWords(ctx, headDev, 2, opts...)
	if err != nil {
		return 0, err
	}
	// リトルエンディアン合成: 下位ワード(words[0]), 上位ワード(words[1])
	val := uint32(words[0]) | (uint32(words[1]) << 16)
	return int32(val), nil
}

func (c *clientImpl) WriteInt32(ctx context.Context, headDev string, value int32, opts ...CallOption) error {
	uVal := uint32(value)
	words := []uint16{
		uint16(uVal & 0xFFFF),
		uint16((uVal >> 16) & 0xFFFF),
	}
	return c.BatchWriteWords(ctx, headDev, words, opts...)
}

func (c *clientImpl) ReadUint32(ctx context.Context, headDev string, opts ...CallOption) (uint32, error) {
	val, err := c.ReadInt32(ctx, headDev, opts...)
	return uint32(val), err
}

func (c *clientImpl) WriteUint32(ctx context.Context, headDev string, value uint32, opts ...CallOption) error {
	return c.WriteInt32(ctx, headDev, int32(value), opts...)
}

func (c *clientImpl) ReadInt64(ctx context.Context, headDev string, opts ...CallOption) (int64, error) {
	words, err := c.BatchReadWords(ctx, headDev, 4, opts...)
	if err != nil {
		return 0, err
	}
	val := uint64(words[0]) |
		(uint64(words[1]) << 16) |
		(uint64(words[2]) << 32) |
		(uint64(words[3]) << 48)
	return int64(val), nil
}

func (c *clientImpl) WriteInt64(ctx context.Context, headDev string, value int64, opts ...CallOption) error {
	uVal := uint64(value)
	words := []uint16{
		uint16(uVal & 0xFFFF),
		uint16((uVal >> 16) & 0xFFFF),
		uint16((uVal >> 32) & 0xFFFF),
		uint16((uVal >> 48) & 0xFFFF),
	}
	return c.BatchWriteWords(ctx, headDev, words, opts...)
}

func (c *clientImpl) ReadUint64(ctx context.Context, headDev string, opts ...CallOption) (uint64, error) {
	val, err := c.ReadInt64(ctx, headDev, opts...)
	return uint64(val), err
}

func (c *clientImpl) WriteUint64(ctx context.Context, headDev string, value uint64, opts ...CallOption) error {
	return c.WriteInt64(ctx, headDev, int64(value), opts...)
}

func (c *clientImpl) ReadFloat32(ctx context.Context, headDev string, opts ...CallOption) (float32, error) {
	uVal, err := c.ReadUint32(ctx, headDev, opts...)
	if err != nil {
		return 0, err
	}
	return math.Float32frombits(uVal), nil
}

func (c *clientImpl) WriteFloat32(ctx context.Context, headDev string, value float32, opts ...CallOption) error {
	uVal := math.Float32bits(value)
	return c.WriteUint32(ctx, headDev, uVal, opts...)
}

func (c *clientImpl) ReadFloat64(ctx context.Context, headDev string, opts ...CallOption) (float64, error) {
	uVal, err := c.ReadUint64(ctx, headDev, opts...)
	if err != nil {
		return 0, err
	}
	return math.Float64frombits(uVal), nil
}

func (c *clientImpl) WriteFloat64(ctx context.Context, headDev string, value float64, opts ...CallOption) error {
	uVal := math.Float64bits(value)
	return c.WriteUint64(ctx, headDev, uVal, opts...)
}

func (c *clientImpl) ReadString(ctx context.Context, headDev string, lengthInBytes int, opts ...CallOption) (string, error) {
	bytes, err := c.ReadRawBytes(ctx, headDev, lengthInBytes, opts...)
	if err != nil {
		return "", err
	}
	// ヌル終端 (0x00) があればそこで切る
	str := string(bytes)
	if idx := strings.IndexByte(str, 0); idx != -1 {
		str = str[:idx]
	}
	return str, nil
}

func (c *clientImpl) WriteString(ctx context.Context, headDev string, text string, opts ...CallOption) error {
	return c.WriteRawBytes(ctx, headDev, []byte(text), opts...)
}

// --- 一括（ブロック）読み書き ---

func (c *clientImpl) BatchReadBits(ctx context.Context, headDev string, count uint16, opts ...CallOption) ([]bool, error) {
	dev, err := device.ParseDevice(headDev)
	if err != nil {
		return nil, err
	}
	req, err := c.framer.BuildBatchRead(dev, count, true)
	if err != nil {
		return nil, err
	}
	resp, err := c.execute(ctx, req, false, opts...)
	if err != nil {
		return nil, err
	}
	payload, err := c.framer.ParseResponse(req, resp)
	if err != nil {
		return nil, err
	}

	// ビット応答のアンパック
	// 3Eフレームのビット読出しでは各バイトに2点(上位/下位ニブル)または1点/1バイト
	// 3E仕様: 1点あたり1ニブル (0x10=ON, 0x00=OFF / 下位ニブル=次ビット)
	results := make([]bool, count)
	if c.cfg.Frame == FrameType1E {
		// 1Eフレーム ビット読出し: 各バイトに2点 (上位ニブル / 下位ニブル)
		for i := 0; i < int(count); i++ {
			byteIdx := i / 2
			if byteIdx >= len(payload) {
				break
			}
			b := payload[byteIdx]
			if i%2 == 0 {
				results[i] = (b & 0xF0) != 0
			} else {
				results[i] = (b & 0x0F) != 0
			}
		}
	} else {
		// 3E/4Eフレーム ビット読出し: 1バイトに2点(上位/下位ニブル)
		for i := 0; i < int(count); i++ {
			byteIdx := i / 2
			if byteIdx >= len(payload) {
				break
			}
			b := payload[byteIdx]
			if i%2 == 0 {
				results[i] = (b & 0x10) != 0
			} else {
				results[i] = (b & 0x01) != 0
			}
		}
	}
	return results, nil
}

func (c *clientImpl) BatchWriteBits(ctx context.Context, headDev string, values []bool, opts ...CallOption) error {
	dev, err := device.ParseDevice(headDev)
	if err != nil {
		return err
	}
	rawBytes := make([]byte, len(values))
	for i, v := range values {
		if v {
			rawBytes[i] = 1
		} else {
			rawBytes[i] = 0
		}
	}
	req, err := c.framer.BuildBatchWrite(dev, rawBytes, true)
	if err != nil {
		return err
	}
	resp, err := c.execute(ctx, req, true, opts...)
	if err != nil {
		return err
	}
	_, err = c.framer.ParseResponse(req, resp)
	return err
}

func (c *clientImpl) BatchReadWords(ctx context.Context, headDev string, count uint16, opts ...CallOption) ([]uint16, error) {
	dev, err := device.ParseDevice(headDev)
	if err != nil {
		return nil, err
	}
	req, err := c.framer.BuildBatchRead(dev, count, false)
	if err != nil {
		return nil, err
	}
	resp, err := c.execute(ctx, req, false, opts...)
	if err != nil {
		return nil, err
	}
	payload, err := c.framer.ParseResponse(req, resp)
	if err != nil {
		return nil, err
	}

	words := make([]uint16, count)
	for i := 0; i < int(count); i++ {
		offset := i * 2
		if offset+2 <= len(payload) {
			words[i] = binary.LittleEndian.Uint16(payload[offset : offset+2])
		}
	}
	return words, nil
}

func (c *clientImpl) BatchWriteWords(ctx context.Context, headDev string, values []uint16, opts ...CallOption) error {
	dev, err := device.ParseDevice(headDev)
	if err != nil {
		return err
	}
	data := make([]byte, len(values)*2)
	for i, v := range values {
		binary.LittleEndian.PutUint16(data[i*2:i*2+2], v)
	}
	req, err := c.framer.BuildBatchWrite(dev, data, false)
	if err != nil {
		return err
	}
	resp, err := c.execute(ctx, req, true, opts...)
	if err != nil {
		return err
	}
	_, err = c.framer.ParseResponse(req, resp)
	return err
}

// --- ランダム読み書き ---

func (c *clientImpl) RandomReadWords(ctx context.Context, wordDevs []string, dwordDevs []string, opts ...CallOption) ([]uint16, []uint32, error) {
	wDevs := make([]device.Device, len(wordDevs))
	for i, s := range wordDevs {
		d, err := device.ParseDevice(s)
		if err != nil {
			return nil, nil, err
		}
		wDevs[i] = d
	}
	dwDevs := make([]device.Device, len(dwordDevs))
	for i, s := range dwordDevs {
		d, err := device.ParseDevice(s)
		if err != nil {
			return nil, nil, err
		}
		dwDevs[i] = d
	}

	req, err := c.framer.BuildRandomRead(wDevs, dwDevs)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.execute(ctx, req, false, opts...)
	if err != nil {
		return nil, nil, err
	}
	payload, err := c.framer.ParseResponse(req, resp)
	if err != nil {
		return nil, nil, err
	}

	// ペイロード解凍
	words := make([]uint16, len(wordDevs))
	dwords := make([]uint32, len(dwordDevs))

	offset := 0
	for i := range words {
		if offset+2 <= len(payload) {
			words[i] = binary.LittleEndian.Uint16(payload[offset : offset+2])
			offset += 2
		}
	}
	for i := range dwords {
		if offset+4 <= len(payload) {
			dwords[i] = binary.LittleEndian.Uint32(payload[offset : offset+4])
			offset += 4
		}
	}
	return words, dwords, nil
}

func (c *clientImpl) RandomWriteWords(ctx context.Context, wordDevs []string, wordVals []uint16, dwordDevs []string, dwordVals []uint32, opts ...CallOption) error {
	wDevs := make([]device.Device, len(wordDevs))
	for i, s := range wordDevs {
		d, err := device.ParseDevice(s)
		if err != nil {
			return err
		}
		wDevs[i] = d
	}
	dwDevs := make([]device.Device, len(dwordDevs))
	for i, s := range dwordDevs {
		d, err := device.ParseDevice(s)
		if err != nil {
			return err
		}
		dwDevs[i] = d
	}

	req, err := c.framer.BuildRandomWriteWords(wDevs, wordVals, dwDevs, dwordVals)
	if err != nil {
		return err
	}
	resp, err := c.execute(ctx, req, true, opts...)
	if err != nil {
		return err
	}
	_, err = c.framer.ParseResponse(req, resp)
	return err
}

func (c *clientImpl) RandomWriteBits(ctx context.Context, bitDevs []string, bitVals []bool, opts ...CallOption) error {
	bDevs := make([]device.Device, len(bitDevs))
	for i, s := range bitDevs {
		d, err := device.ParseDevice(s)
		if err != nil {
			return err
		}
		bDevs[i] = d
	}

	req, err := c.framer.BuildRandomWriteBits(bDevs, bitVals)
	if err != nil {
		return err
	}
	resp, err := c.execute(ctx, req, true, opts...)
	if err != nil {
		return err
	}
	_, err = c.framer.ParseResponse(req, resp)
	return err
}

// --- 生データ (Raw / HEX) 読み書き & コマンド実行 ---

func (c *clientImpl) ReadRawBytes(ctx context.Context, headDev string, byteLength int, opts ...CallOption) ([]byte, error) {
	if byteLength <= 0 {
		return nil, nil
	}
	// 1ワード=2バイトのため、必要ワード数を計算 (奇数の場合は切り上げ)
	wordCount := uint16((byteLength + 1) / 2)
	words, err := c.BatchReadWords(ctx, headDev, wordCount, opts...)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, len(words)*2)
	for i, w := range words {
		binary.LittleEndian.PutUint16(raw[i*2:i*2+2], w)
	}
	return raw[:byteLength], nil
}

func (c *clientImpl) WriteRawBytes(ctx context.Context, headDev string, data []byte, opts ...CallOption) error {
	if len(data) == 0 {
		return nil
	}
	// ワード境界にアライン (奇数バイトの場合は末尾0パディング)
	dataCopy := data
	if len(dataCopy)%2 != 0 {
		dataCopy = append(dataCopy, 0x00)
	}
	wordCount := len(dataCopy) / 2
	words := make([]uint16, wordCount)
	for i := 0; i < wordCount; i++ {
		words[i] = binary.LittleEndian.Uint16(dataCopy[i*2 : i*2+2])
	}
	return c.BatchWriteWords(ctx, headDev, words, opts...)
}

func (c *clientImpl) ReadHexString(ctx context.Context, headDev string, wordCount int, opts ...CallOption) (string, error) {
	bytes, err := c.ReadRawBytes(ctx, headDev, wordCount*2, opts...)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(bytes)), nil
}

func (c *clientImpl) WriteHexString(ctx context.Context, headDev string, hexStr string, opts ...CallOption) error {
	// 空白やハイフン、0xを取り除く
	cleaned := strings.ReplaceAll(hexStr, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.TrimPrefix(strings.ToLower(cleaned), "0x")

	bytes, err := hex.DecodeString(cleaned)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidHexData, err)
	}
	return c.WriteRawBytes(ctx, headDev, bytes, opts...)
}

func (c *clientImpl) ExecuteCommand(ctx context.Context, command uint16, subCommand uint16, reqData []byte, opts ...CallOption) ([]byte, error) {
	req, err := c.framer.BuildRawCommand(command, subCommand, reqData)
	if err != nil {
		return nil, err
	}
	resp, err := c.execute(ctx, req, true, opts...)
	if err != nil {
		return nil, err
	}
	return c.framer.ParseResponse(req, resp)
}
