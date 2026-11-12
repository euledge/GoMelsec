package buffer

import (
	"sync"
)

// DefaultBufferSize は一般的なMCプロトコルフレーム送受信バッファの初期サイズです（4KB）。
const DefaultBufferSize = 4096

// BufferPool は送受信バイトスライスの再利用を管理するプールです。
// GCプレッシャーを大幅に軽減し、ゼロアロケーション指向の通信を実現します。
type BufferPool struct {
	pool sync.Pool
}

// GlobalPool はパッケージ共通のバッファプールです。
var GlobalPool = NewBufferPool(DefaultBufferSize)

// NewBufferPool は指定サイズのバッファを生成する新しいプールを作成します。
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, size)
				return &b
			},
		},
	}
}

// Get はプールからバイトスライスのポインタを取得します。
func (p *BufferPool) Get() *[]byte {
	return p.pool.Get().(*[]byte)
}

// Put は使用済みのバイトスライスをプールへ返却します。
func (p *BufferPool) Put(b *[]byte) {
	if b == nil {
		return
	}
	// 長さをキャパシティまでリセットして返却
	*b = (*b)[:cap(*b)]
	p.pool.Put(b)
}

// GetSlice は指定長にスライスされたバイトスライスを取得するヘルパーです。
func (p *BufferPool) GetSlice(length int) (*[]byte, []byte) {
	ptr := p.Get()
	if cap(*ptr) < length {
		// キャパシティが不足している場合は新規アロケーション
		buf := make([]byte, length)
		return &buf, buf
	}
	slice := (*ptr)[:length]
	return ptr, slice
}
