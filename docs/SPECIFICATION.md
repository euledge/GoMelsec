# 三菱PLC (MELSEC) 通信ライブラリ「GoMelsec」詳細仕様書

## 1. プロジェクト概要

### 1.1 目的
Go言語による三菱電機製プログラマブルコントローラ（MELSEC）との高速・堅牢なソケット通信ライブラリ。
既存のPython（pymcprotocol）やJava（JulienSun/melsec）、既存Go実装の強みを取り入れ、現場のFAシステム・IoTゲートウェイ・データロガーで真に実用に耐えうる高品質なクライアントを提供する。

### 1.2 主な特徴
- **マルチフレーム対応**: 1E（A/FX互換）、3E（Q/L/iQ-R/FX5U標準）、4E（高信頼・シリアルNo検証）を透過的にサポート。
- **マルチプロトコル・PLCシリーズ対応**: TCP/UDP両対応。Q/Lシリーズ、MELSEC iQ-R、MELSEC iQ-F（FX5U/FX5UJ）、FX3シリーズ（FX3U/FX3G + ENET）に対応。
- **高速通信（低レイテンシ・高スループット）**: `sync.Pool` による送受信バッファの再利用、ゼロアロケーション指向設計。
- **堅牢な自動復旧**: ソケット瞬停・切断時の自動再接続、指数バックオフ付きリトライ機構。
- **通信死活監視（Health Check）**: 3E/4Eのループバックテスト（0619H）を利用した、メモリ非侵襲なヘルスチェックとレイテンシ測定。
- **直感的かつ柔軟なAPI**: ビット・ワードの単一/一括/ランダム読み書き、16/32/64bit整数、単精度/倍精度実数、文字列、生バイト列、16進文字列（HEX）の直接入出力。

---

## 2. システムアーキテクチャ

```
┌────────────────────────────────────────────────────────────────────────┐
│                              Client API                                │
│   ・単一/一括/ランダム読み書き (Bit / Word)                            │
│   ・型安全ヘルパー (Int16/32/64, Float32/64, String)                   │
│   ・生データ/HEX操作 (RawBytes, HexString, ExecuteCommand)             │
│   ・死活監視 (Ping, PingLatency)                                      │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │                                │
                    ▼                                ▼
        ┌───────────────────────┐        ┌───────────────────────┐
        │   Device Parser       │        │  Retry & Auto-Connect │
        │ ("D100" -> Code/Addr) │        │ (Exponential Backoff) │
        └───────────┬───────────┘        └───────────┬───────────┘
                    │                                │
                    ▼                                ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Framer Layer (Strategy)                         │
│   ┌────────────────────┬────────────────────┬────────────────────┐     │
│   │     1E Framer      │     3E Framer      │     4E Framer      │     │
│   │ (A互換/サブヘッダ直)│ (0x5000 / 0xD000)  │ (0x5400 / 0xD400)  │     │
│   │                    │ (Cmd/Subcmd方式)   │ (シリアルNo整合性) │     │
│   └────────────────────┴────────────────────┴────────────────────┘     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                            Transport Layer                             │
│                  TCP (net.TCPConn) / UDP (net.UDPConn)                 │
│                      (Buffer Pool / Non-blocking)                      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. サポート対象とフレーム仕様

### 3.1 対象PLCシリーズと対応フレーム
| PLCシリーズ | 定義定数 | 推奨フレーム | トランスポート | 特有の注意事項 |
| :--- | :--- | :--- | :--- | :--- |
| **Q / L / QnA** | `PLCSeriesQ` | **3E** | TCP / UDP | 最も標準的。バイナリモード |
| **MELSEC iQ-R** | `PLCSeriesIQR` | **3E / 4E** | TCP / UDP | 4EフレームでメッセージID検証可能 |
| **MELSEC iQ-F**<br>(FX5U / FX5UJ / FX5S) | `PLCSeriesIQF` | **3E / 4E** | TCP / UDP | 内蔵Ethernetで3E/4E標準サポート |
| **FX3シリーズ**<br>(FX3U / FX3G + ENET) | `PLCSeriesFX` | **1E** (一部3E) | TCP / UDP | A互換1Eフレーム。FX特有デバイス有 |

### 3.2 フレームヘッダ構造比較（バイナリモード）
- **1Eフレーム**:
  - 要求: `[サブヘッダ(1B: 0x00~0x03)] [PC番号(1B)] [監視タイマ(2B)] [先頭アドレス(4B)] [デバイスコード(1B)] [点数(1B/2B)] [書込データ...]`
  - 応答: `[サブヘッダ(1B: 0x80/0x5B)] [エラーコード(1B: 異常時のみ)] [データ部...]`
- **3Eフレーム**:
  - 要求: `[サブヘッダ(2B: 0x5000)] [NW(1B)] [PC(1B)] [Unit(2B)] [局番(1B)] [データ長(2B)] [CPUタイマ(2B)] [コマンド(2B)] [サブコマンド(2B)] [データ部...]`
  - 応答: `[サブヘッダ(2B: 0xD000)] [NW(1B)] [PC(1B)] [Unit(2B)] [局番(1B)] [データ長(2B)] [終了コード(2B: 0x0000=正常)] [データ部...]`
- **4Eフレーム**:
  - 要求: `[サブヘッダ(2B: 0x5400)] [シリアルNo(2B)] [予約(2B)]` + 3Eフレーム部
  - 応答: `[サブヘッダ(2B: 0xD400)] [シリアルNo(2B)] [予約(2B)]` + 3Eフレーム部

---

## 4. デバイス仕様とパース体系

デバイス指定文字列（例: `"D100"`, `"X01A"`, `"M100"`, `"S10"`）を内部でパースし、PLCシリーズとフレーム種別に応じたバイナリデバイスコードに変換します。

### 4.1 対応デバイス一覧
| デバイス記号 | 名称 | 種別 | 基数 | 3E/4Eコード | 1Eコード | 備考 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **D** | データレジスタ | ワード | 10進 | `0xA8` | `0x44` ('D') | 最頻出 |
| **M** | 内部リレー | ビット | 10進 | `0x90` | `0x4D` ('M') | M8000番台はFX特殊 |
| **SM** | 特殊リレー | ビット | 10進 | `0x91` | - | iQ-R / iQ-F / Q |
| **SD** | 特殊レジスタ | ワード | 10進 | `0xA9` | - | iQ-R / iQ-F / Q |
| **X** | 入力 | ビット | **16進** | `0x9C` | `0x58` ('X') | X0〜X1F等 |
| **Y** | 出力 | ビット | **16進** | `0x9D` | `0x59` ('Y') | Y0〜Y1F等 |
| **W** | リンクレジスタ | ワード | **16進** | `0xB4` | `0x57` ('W') | W0〜WFFF等 |
| **B** | リンクリレー | ビット | **16進** | `0xA0` | `0x42` ('B') | B0〜BFFF等 |
| **ZR** | ファイルレジスタ | ワード | 16進/10進 | `0xB0` | - | 連番アクセス |
| **R** | ファイルレジスタ | ワード | 10進 | `0xAF` | `0x52` ('R') | |
| **S** | ステップリレー | ビット | 10進 | `0x98` | `0x53` ('S') | **FX特有 (SFC/歩進)** |
| **TS / TC / TN** | タイマ(接点/コイル/現在値) | ビット/ワード | 10進 | 各種 | 各種 | TN=16bit現在値 |
| **CS / CC / CN** | カウンタ(接点/コイル/現在値)| ビット/ワード | 10進 | 各種 | 各種 | CN=16bit/32bit |

---

## 5. 設定オプション（Config）

```go
type TransportType string
const (
    TransportTCP TransportType = "tcp"
    TransportUDP TransportType = "udp"
)

type FrameType string
const (
    FrameType1E FrameType = "1E"
    FrameType3E FrameType = "3E"
    FrameType4E FrameType = "4E"
)

type PLCSeries string
const (
    PLCSeriesQ   PLCSeries = "Q"   // Q/L/QnA
    PLCSeriesIQR PLCSeries = "IQR" // iQ-R
    PLCSeriesIQF PLCSeries = "IQF" // iQ-F (FX5U)
    PLCSeriesFX  PLCSeries = "FX"  // FX3U/FX3G
)

type Config struct {
    // 接続設定
    Host          string        // 例: "192.168.1.10"
    Port          int           // 例: 5002
    Transport     TransportType // TransportTCP / TransportUDP
    Frame         FrameType     // FrameType1E / FrameType3E / FrameType4E
    PLCSeries     PLCSeries     // 対象PLC種別

    // ロギング設定 (運用・障害診断用)
    Logger     *slog.Logger // 構造化ロガー (nilの場合はログ出力なし)
    DumpPacket bool         // 送受信パケットの16進ダンプをDebugレベルで出力するか

    // タイムアウト設定
    ConnectTimeout time.Duration // 接続確立タイムアウト (デフォルト: 3s)
    Timeout        time.Duration // 送受信タイムアウト (デフォルト: 2s)

    // 自動再接続設定
    AutoReconnect bool // 通信切断時の自動再接続を行うか

    // リトライポリシー設定
    Retry RetryConfig

    // ヘルスチェック (死活監視) 設定
    EnableHealthCheck        bool          // 定期監視を有効化
    HealthCheckInterval      time.Duration // 監視間隔 (デフォルト: 5s)
    HealthCheckTimeout       time.Duration // Pingタイムアウト (デフォルト: 1s)
    HealthCheckFailThreshold int           // 再接続判定の連続失敗回数 (デフォルト: 2)
    HealthCheckDevice1E      string        // 1E用監視デバイス (デフォルト: "D0")

    // イベントコールバック
    OnConnect      func()
    OnDisconnect   func(err error)
    OnHealthChange func(healthy bool, latency time.Duration)

    // 3E/4E 固有ルーティング設定
    NetworkNumber      byte   // デフォルト: 0x00
    PCNumber           byte   // デフォルト: 0xFF
    DestinationUnit    uint16 // デフォルト: 0x03FF (自局CPU)
    DestinationStation byte   // デフォルト: 0x00
    CPUTimer           uint16 // デフォルト: 0x0010 (4s)
}

type RetryConfig struct {
    MaxRetries      int           // 最大リトライ回数 (0で無効)
    InitialInterval time.Duration // 初回待機時間 (例: 100ms)
    MaxInterval     time.Duration // 最大待機上限 (例: 2s)
    Multiplier      float64       // 指数バックオフ係数 (例: 1.5)
    RetryOnWrite    bool          // 書込系APIでもリトライするか
}
```

---

## 6. 公開 API インタフェース（`Client`）

```go
type Client interface {
    // ==========================================
    // 1. 接続管理・ヘルスチェック
    // ==========================================
    Connect(ctx context.Context) error
    Close() error
    IsConnected() bool
    Ping(ctx context.Context) error
    PingLatency(ctx context.Context) (time.Duration, error)
    IsHealthy() bool
    LastLatency() time.Duration

    // ==========================================
    // 2. 単一読み書き (便利メソッド)
    // ==========================================
    ReadBit(ctx context.Context, device string, opts ...CallOption) (bool, error)
    WriteBit(ctx context.Context, device string, value bool, opts ...CallOption) error
    ReadWord(ctx context.Context, device string, opts ...CallOption) (uint16, error)
    WriteWord(ctx context.Context, device string, value uint16, opts ...CallOption) error

    // ==========================================
    // 3. 型安全マルチワード読み書き
    // ==========================================
    // 16bit 整数
    ReadInt16(ctx context.Context, device string, opts ...CallOption) (int16, error)
    WriteInt16(ctx context.Context, device string, value int16, opts ...CallOption) error
    ReadUint16(ctx context.Context, device string, opts ...CallOption) (uint16, error)
    WriteUint16(ctx context.Context, device string, value uint16, opts ...CallOption) error

    // 32bit 整数 (DINT / Long: 2ワード)
    ReadInt32(ctx context.Context, headDevice string, opts ...CallOption) (int32, error)
    WriteInt32(ctx context.Context, headDevice string, value int32, opts ...CallOption) error
    ReadUint32(ctx context.Context, headDevice string, opts ...CallOption) (uint32, error)
    WriteUint32(ctx context.Context, headDevice string, value uint32, opts ...CallOption) error

    // 64bit 整数 (LINT: 4ワード)
    ReadInt64(ctx context.Context, headDevice string, opts ...CallOption) (int64, error)
    WriteInt64(ctx context.Context, headDevice string, value int64, opts ...CallOption) error
    ReadUint64(ctx context.Context, headDevice string, opts ...CallOption) (uint64, error)
    WriteUint64(ctx context.Context, headDevice string, value uint64, opts ...CallOption) error

    // 浮動小数点数 (実数)
    ReadFloat32(ctx context.Context, headDevice string, opts ...CallOption) (float32, error) // REAL / 2ワード
    WriteFloat32(ctx context.Context, headDevice string, value float32, opts ...CallOption) error
    ReadFloat64(ctx context.Context, headDevice string, opts ...CallOption) (float64, error) // LREAL / 4ワード (Double)
    WriteFloat64(ctx context.Context, headDevice string, value float64, opts ...CallOption) error

    // 文字列 (ASCII)
    ReadString(ctx context.Context, headDevice string, lengthInBytes int, opts ...CallOption) (string, error)
    WriteString(ctx context.Context, headDevice string, text string, opts ...CallOption) error

    // ==========================================
    // 4. 一括（ブロック）読み書き (Batch Read / Write)
    // ==========================================
    BatchReadBits(ctx context.Context, headDevice string, count uint16, opts ...CallOption) ([]bool, error)
    BatchWriteBits(ctx context.Context, headDevice string, values []bool, opts ...CallOption) error
    BatchReadWords(ctx context.Context, headDevice string, count uint16, opts ...CallOption) ([]uint16, error)
    BatchWriteWords(ctx context.Context, headDevice string, values []uint16, opts ...CallOption) error

    // ==========================================
    // 5. ランダム読み書き (Random Read / Write)
    // ==========================================
    RandomReadWords(ctx context.Context, wordDevices []string, dwordDevices []string, opts ...CallOption) (words []uint16, dwords []uint32, err error)
    RandomWriteWords(ctx context.Context, wordDevices []string, wordValues []uint16, dwordDevices []string, dwordValues []uint32, opts ...CallOption) error
    RandomWriteBits(ctx context.Context, bitDevices []string, bitValues []bool, opts ...CallOption) error

    // ==========================================
    // 6. 生データ (Raw / HEX) 読み書き & コマンド実行
    // ==========================================
    ReadRawBytes(ctx context.Context, headDevice string, byteLength int, opts ...CallOption) ([]byte, error)
    WriteRawBytes(ctx context.Context, headDevice string, data []byte, opts ...CallOption) error
    ReadHexString(ctx context.Context, headDevice string, wordCount int, opts ...CallOption) (string, error)
    WriteHexString(ctx context.Context, headDevice string, hexStr string, opts ...CallOption) error
    ExecuteCommand(ctx context.Context, command uint16, subCommand uint16, requestData []byte, opts ...CallOption) ([]byte, error)
}
```

---

## 7. エラーハンドリング・再接続・リトライ機構

### 7.1 エラーの分類
ライブラリ内部でエラーを3種類に分類し、適切なアクションを実行します。
1. **一時的通信エラー（Transient Error）**:
   - タイムアウト、パケットロス、PLCビジー。
   - アクション: バックオフ待機して再送。
2. **接続切断エラー（Disconnect Error）**:
   - `io.EOF`、`syscall.ECONNRESET`、Broken Pipe。
   - アクション: ソケットをクローズし、即時再接続（Connect）を実行後、再送。
3. **恒久的論理エラー（Permanent Error）**:
   - デバイス名構文不正、PLC異常終了コード（アドレス範囲外 `0x4000`、コマンド不正等）。
   - アクション: リトライせず即座にエラー返却。

### 7.2 指数バックオフ（Exponential Backoff）
リトライ間隔の計算式:
$$\text{Interval} = \min(\text{InitialInterval} \times \text{Multiplier}^{(\text{attempt}-1)}, \text{MaxInterval})$$
（例: 100ms → 150ms → 225ms → 上限2000ms）

---

## 8. 高速化（パフォーマンス最適化）設計

1. **ゼロアロケーション指向バッファリング**:
   `sync.Pool` を用いて、リクエスト組み立て用・レスポンス受信用スライス（最大4096バイト）を使い回し、大量アクセス時のGC停止時間を最小化。
2. **バイナリパッキングの最適化**:
   リフレクションを伴う重いシリアライザを排除し、直接 `binary.LittleEndian.PutUint16` 等でスライスを構築。
3. **接続多重化・スレッドセーフ**:
   内部Mutexでセッション排他を行い、複数ゴルーチンからの同時アクセスを安全に保護。

---

## 9. 運用ロギング & 障害診断仕様

実際のFA現場・IoTシステムでの障害調査を迅速化するため、Go標準の構造化ロガー `*slog.Logger` に対応しています。

### 9.1 出力されるログ情報一覧
| ログレベル | トリガー・内容 | 含まれる主要フィールド |
| :--- | :--- | :--- |
| **DEBUG** | 送受信パケット（`DumpPacket=true` 時） | `bytes` (パケット長), `hex` (16進ダンプ文字列) |
| **DEBUG** | 接続開始・ソケット状態 | `host`, `port`, `transport`, `frame` |
| **INFO** | 接続成功 / 切断 / 復旧 | `remote_addr`, `latency` (復旧時のRTT) |
| **WARN** | 一時的通信エラー & リトライ待機 | `attempt`, `max_retries`, `next_attempt`, `interval`, `error` |
| **WARN** | ソケット切断検知 & 自動再接続トリガー | `error` (EOF / Connection Reset) |
| **ERROR** | リトライ上限到達による最終失敗 | `total_attempts`, `last_error` |
| **ERROR** | PLC異常終了コード返却 | `end_code`, `description` (マニュアル解説日本語メッセージ) |
| **ERROR** | ヘルスチェック連続失敗による切断判定 | `consecutive_failures`, `threshold` |

### 9.2 PLCエラーコード解説機能
PLCから異常終了コード（例: `0xC059`, `0x4000`）が返却された場合、マニュアルを調べなくてもログを見るだけで即座に原因が特定できるよう、解説メッセージを自動付加します：
- `0x4000`: 指定されたデバイスコードまたはアドレスが存在しないか、範囲外です
- `0x4001`: 指定されたデバイスの点数がアクセス可能範囲を超えています
- `0xC059`: 指定されたコマンドまたはサブコマンドはPLCでサポートされていません
- `0xC05B`: CPUが書込禁止（RUN中書込不可など）状態のため書き込めません

