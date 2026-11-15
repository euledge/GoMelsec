package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"gomelsec"
)

// mock1EServer はテスト・検証用の簡易 1E フレーム (バイナリモード) PLC サーバーです。
type mock1EServer struct {
	listener net.Listener
	dMemory  [1000]uint16
	stopped  bool
}

func startMock1EServer(addr string) (*mock1EServer, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	server := &mock1EServer{listener: l}
	// D0~D4 に 0~4 を初期設定
	for i := 0; i <= 4; i++ {
		server.dMemory[i] = uint16(i)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go server.handleConn(conn)
		}
	}()

	return server, nil
}

func (s *mock1EServer) handleConn(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF && !s.stopped {
				// 切断
			}
			return
		}

		req := buf[:n]
		if len(req) < 12 {
			continue
		}

		subHeader := req[0]
		addr := int(req[4]) | (int(req[5]) << 8) | (int(req[6]) << 16) | (int(req[7]) << 24)
		code := req[8]
		count := int(req[10]) | (int(req[11]) << 8)

		switch subHeader {
		case 0x01: // ワード単位読出し (SubHeader1EWordRead)
			if code == 0x44 { // 'D'
				resp := make([]byte, 2+count*2)
				resp[0] = 0x81 // 正常終了レスポンス (0x80 | 0x01)
				resp[1] = 0x00 // 完了コード (0x00=正常)
				for i := 0; i < count; i++ {
					targetAddr := addr + i
					val := uint16(0)
					if targetAddr < len(s.dMemory) {
						val = s.dMemory[targetAddr]
					}
					resp[2+i*2] = byte(val & 0xFF)
					resp[2+i*2+1] = byte(val >> 8)
				}
				_, _ = conn.Write(resp)
			}
		case 0x03: // ワード単位書込み (SubHeader1EWordWrite)
			if code == 0x44 { // 'D'
				data := req[12:]
				for i := 0; i < count; i++ {
					targetAddr := addr + i
					if targetAddr < len(s.dMemory) && i*2+2 <= len(data) {
						s.dMemory[targetAddr] = uint16(data[i*2]) | (uint16(data[i*2+1]) << 8)
					}
				}
				resp := []byte{0x83, 0x00} // 正常終了レスポンス + 完了コード 0x00
				_, _ = conn.Write(resp)
			}
		default:
			// 未サポートコマンドはエラー応答 (0x5B + エラーコード 0xFF)
			resp := []byte{0x5B, 0xFF}
			_, _ = conn.Write(resp)
		}
	}
}

func (s *mock1EServer) Close() {
	s.stopped = true
	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func main() {
	hostFlag := flag.String("host", "127.0.0.1", "PLCのIPアドレス")
	portFlag := flag.Int("port", 8031, "ポート番号 (デフォルト: 8031)")
	useMockFlag := flag.Bool("mock", false, "内部モックPLCサーバーを起動してテストする")
	writeFlag := flag.Bool("write", true, "テスト前にD0~D4に0~4を書き込む")
	flag.Parse()

	fmt.Printf("=========================================\n")
	fmt.Printf("  MELSEC 1Eフレーム (TCP/Binary) テスト\n")
	fmt.Printf("=========================================\n")
	fmt.Printf("接続先: %s:%d\n", *hostFlag, *portFlag)
	fmt.Printf("プロトコル: 1Eフレーム (バイナリモード / TCP)\n\n")

	// モックサーバーの起動（-mock オプション指定時）
	if *useMockFlag {
		addr := fmt.Sprintf("%s:%d", *hostFlag, *portFlag)
		mock, err := startMock1EServer(addr)
		if err != nil {
			fmt.Printf("[エラー] モックサーバーの起動に失敗しました (%s): %v\n", addr, err)
			os.Exit(1)
		}
		defer mock.Close()
		fmt.Printf(">> モックサーバーを %s で起動しました (D0=0, D1=1, D2=2, D3=3, D4=4)\n\n", addr)
	}

	// 構造化ロガー設定 (パケットのHEXダンプを出力)
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(logHandler)

	// 1Eフレーム + TCP + バイナリモード設定
	cfg := gomelsec.DefaultConfig(*hostFlag, *portFlag)
	cfg.Transport = gomelsec.TransportTCP
	cfg.Frame = gomelsec.FrameType1E
	cfg.Format = gomelsec.FormatBinary
	cfg.PLCSeries = gomelsec.PLCSeriesFX
	cfg.Logger = logger
	cfg.DumpPacket = true // 送受信パケットのHEXダンプを表示
	cfg.Timeout = 3 * time.Second
	cfg.AutoReconnect = false
	cfg.HealthCheckDevice1E = "D0"

	client, err := gomelsec.NewClient(cfg)
	if err != nil {
		fmt.Printf("[エラー] クライアント生成失敗: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fmt.Printf("[1/3] PLCに接続中 (%s:%d)...\n", *hostFlag, *portFlag)
	if err := client.Connect(ctx); err != nil {
		fmt.Printf("[接続失敗] %v\n", err)
		if !*useMockFlag {
			fmt.Println("\n※ 実機PLCまたはシミュレータが起動していない場合は、")
			fmt.Println("  go run ./examples/test_1e/main.go -mock")
			fmt.Println("  を指定して内部モックサーバーで動作確認を行えます。")
		}
		os.Exit(1)
	}
	fmt.Printf("[接続成功] Connected!\n\n")

	// 0. テストデータ書き込み (-write 指定時)
	if *writeFlag {
		fmt.Println("[準備] D0~D4 にテスト値 (0, 1, 2, 3, 4) を一括書き込み中...")
		if err := client.BatchWriteWords(ctx, "D0", []uint16{0, 1, 2, 3, 4}); err != nil {
			fmt.Printf("[書込み失敗] %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[書込み完了] D0~D4 に [0, 1, 2, 3, 4] を書き込みました。\n\n")
	}

	// 1. D0~D4 一括読み出し (BatchReadWords)
	fmt.Println("[2/3] D0~D4 一括読み出し (BatchReadWords(ctx, \"D0\", 5))...")
	words, err := client.BatchReadWords(ctx, "D0", 5)
	if err != nil {
		fmt.Printf("[読出し失敗] %v\n", err)
		os.Exit(1)
	}

	fmt.Println("取得結果:")
	allMatch := true
	for i, val := range words {
		expected := uint16(i)
		match := (val == expected)
		if !match {
			allMatch = false
		}
		mark := "OK"
		if !match {
			mark = fmt.Sprintf("NG (期待値: %d)", expected)
		}
		fmt.Printf("  D%d = %d  [%s]\n", i, val, mark)
	}

	if allMatch {
		fmt.Printf("\n=> 判定: 【合格】 D0~D4 が期待通り 0~4 の値と一致しました。\n\n")
	} else {
		fmt.Printf("\n=> 判定: 【不一致】 期待値と異なる値が検出されました。\n\n")
	}

	// 2. 単一ワード読み出し (ReadWord) での再確認
	fmt.Println("[3/3] 単一ワード読み出し (ReadWord) での個別確認...")
	for i := 0; i <= 4; i++ {
		dev := fmt.Sprintf("D%d", i)
		val, err := client.ReadWord(ctx, dev)
		if err != nil {
			fmt.Printf("  %s 読み出し失敗: %v\n", dev, err)
			continue
		}
		fmt.Printf("  %s: %d\n", dev, val)
	}

	fmt.Printf("\n=========================================\n")
	fmt.Printf("  テスト完了\n")
	fmt.Printf("=========================================\n")
}
