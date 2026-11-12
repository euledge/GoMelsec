package buffer

import (
	"testing"
)

func TestBufferPool(t *testing.T) {
	pool := NewBufferPool(1024)

	ptr := pool.Get()
	if ptr == nil || len(*ptr) != 1024 {
		t.Fatalf("expected buffer of length 1024, got %v", ptr)
	}

	// データを書き込む
	(*ptr)[0] = 0x50
	(*ptr)[1] = 0x00

	// プールへ返却
	pool.Put(ptr)

	// 再度取得
	ptr2 := pool.Get()
	if ptr2 == nil || cap(*ptr2) < 1024 {
		t.Fatalf("expected buffer with cap >= 1024")
	}
	pool.Put(ptr2)
}

func TestBufferPool_GetSlice(t *testing.T) {
	pool := NewBufferPool(512)

	// 512以内の要求
	ptr, slice := pool.GetSlice(100)
	if len(slice) != 100 {
		t.Fatalf("expected slice length 100, got %d", len(slice))
	}
	pool.Put(ptr)

	// キャパシティを超える要求
	ptrLarge, sliceLarge := pool.GetSlice(2048)
	if len(sliceLarge) != 2048 {
		t.Fatalf("expected slice length 2048, got %d", len(sliceLarge))
	}
	pool.Put(ptrLarge)
}
