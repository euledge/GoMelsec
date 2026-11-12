package gomelsec

import "time"

// CallOptions は個別のAPIリクエスト呼び出しに対するオプションです。
type CallOptions struct {
	MaxRetries    *int
	RetryInterval *time.Duration
	Timeout       *time.Duration
}

// CallOption はオプション設定関数です。
type CallOption func(*CallOptions)

// WithMaxRetries はこの呼び出し限定で最大リトライ回数を指定します。
func WithMaxRetries(n int) CallOption {
	return func(o *CallOptions) {
		o.MaxRetries = &n
	}
}

// WithRetryInterval はこの呼び出し限定でリトライ間隔を指定します。
func WithRetryInterval(d time.Duration) CallOption {
	return func(o *CallOptions) {
		o.RetryInterval = &d
	}
}

// WithTimeout はこの呼び出し限定でタイムアウトを指定します。
func WithTimeout(d time.Duration) CallOption {
	return func(o *CallOptions) {
		o.Timeout = &d
	}
}
