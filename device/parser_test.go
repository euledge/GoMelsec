package device

import (
	"testing"
)

func TestParseDevice(t *testing.T) {
	tests := []struct {
		input       string
		expected    Device
		expectError bool
		code3E      byte
		code1E      byte
		can1E       bool
	}{
		// 10進ワード
		{"D100", Device{Type: DevD, Name: "D", Number: 100, IsBit: false, IsHex: false}, false, 0xA8, 0x44, true},
		{"d0", Device{Type: DevD, Name: "D", Number: 0, IsBit: false, IsHex: false}, false, 0xA8, 0x44, true},
		{"D8000", Device{Type: DevD, Name: "D", Number: 8000, IsBit: false, IsHex: false}, false, 0xA8, 0x44, true}, // FX特殊
		{"SD10", Device{Type: DevSD, Name: "SD", Number: 10, IsBit: false, IsHex: false}, false, 0xA9, 0, false},
		{"R500", Device{Type: DevR, Name: "R", Number: 500, IsBit: false, IsHex: false}, false, 0xAF, 0x52, true},
		{"ZR12345", Device{Type: DevZR, Name: "ZR", Number: 12345, IsBit: false, IsHex: false}, false, 0xB0, 0, false},
		{"ZR0x1A", Device{Type: DevZR, Name: "ZR", Number: 0x1A, IsBit: false, IsHex: true}, false, 0xB0, 0, false},

		// 10進ビット
		{"M10", Device{Type: DevM, Name: "M", Number: 10, IsBit: true, IsHex: false}, false, 0x90, 0x4D, true},
		{"M8000", Device{Type: DevM, Name: "M", Number: 8000, IsBit: true, IsHex: false}, false, 0x90, 0x4D, true}, // FX特殊
		{"SM400", Device{Type: DevSM, Name: "SM", Number: 400, IsBit: true, IsHex: false}, false, 0x91, 0, false},
		{"S20", Device{Type: DevS, Name: "S", Number: 20, IsBit: true, IsHex: false}, false, 0x98, 0x53, true}, // FXステップリレー
		{"L100", Device{Type: DevL, Name: "L", Number: 100, IsBit: true, IsHex: false}, false, 0x92, 0, false},
		{"F5", Device{Type: DevF, Name: "F", Number: 5, IsBit: true, IsHex: false}, false, 0x93, 0x46, true},
		{"V12", Device{Type: DevV, Name: "V", Number: 12, IsBit: true, IsHex: false}, false, 0x94, 0, false},

		// 16進ビット
		{"X0", Device{Type: DevX, Name: "X", Number: 0, IsBit: true, IsHex: true}, false, 0x9C, 0x58, true},
		{"X1F", Device{Type: DevX, Name: "X", Number: 0x1F, IsBit: true, IsHex: true}, false, 0x9C, 0x58, true},
		{"Y2A", Device{Type: DevY, Name: "Y", Number: 0x2A, IsBit: true, IsHex: true}, false, 0x9D, 0x59, true},
		{"B10", Device{Type: DevB, Name: "B", Number: 0x10, IsBit: true, IsHex: true}, false, 0xA0, 0x42, true},
		{"SB1F", Device{Type: DevSB, Name: "SB", Number: 0x1F, IsBit: true, IsHex: true}, false, 0xA1, 0, false},
		{"DX0", Device{Type: DevDX, Name: "DX", Number: 0, IsBit: true, IsHex: true}, false, 0xA2, 0, false},
		{"DY10", Device{Type: DevDY, Name: "DY", Number: 0x10, IsBit: true, IsHex: true}, false, 0xA3, 0, false},

		// 16進ワード
		{"W100", Device{Type: DevW, Name: "W", Number: 0x100, IsBit: false, IsHex: true}, false, 0xB4, 0x57, true},
		{"SW2B", Device{Type: DevSW, Name: "SW", Number: 0x2B, IsBit: false, IsHex: true}, false, 0xB5, 0, false},

		// タイマ・カウンタ
		{"TS0", Device{Type: DevTS, Name: "TS", Number: 0, IsBit: true, IsHex: false}, false, 0xC1, 0x54, true},
		{"TC1", Device{Type: DevTC, Name: "TC", Number: 1, IsBit: true, IsHex: false}, false, 0xC0, 0x54, true},
		{"TN2", Device{Type: DevTN, Name: "TN", Number: 2, IsBit: false, IsHex: false}, false, 0xC2, 0x54, true},
		{"CS10", Device{Type: DevCS, Name: "CS", Number: 10, IsBit: true, IsHex: false}, false, 0xC4, 0x43, true},
		{"CC11", Device{Type: DevCC, Name: "CC", Number: 11, IsBit: true, IsHex: false}, false, 0xC3, 0x43, true},
		{"CN12", Device{Type: DevCN, Name: "CN", Number: 12, IsBit: false, IsHex: false}, false, 0xC5, 0x43, true},

		// エラーケース
		{"", Device{}, true, 0, 0, false},
		{"D", Device{}, true, 0, 0, false},
		{"Z100", Device{}, true, 0, 0, false},
		{"DXYZ", Device{}, true, 0, 0, false},
		{"XGG", Device{}, true, 0, 0, false}, // 16進数ではない
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			dev, err := ParseDevice(tt.input)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error for input %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
			if dev != tt.expected {
				t.Errorf("expected %+v, got %+v", tt.expected, dev)
			}

			// 3Eコード確認
			code3e, err := dev.BinaryCode3E()
			if err != nil {
				t.Fatalf("unexpected 3E code error: %v", err)
			}
			if code3e != tt.code3E {
				t.Errorf("expected 3E code 0x%02X, got 0x%02X", tt.code3E, code3e)
			}

			// 1Eコード確認
			code1e, err := dev.BinaryCode1E()
			if tt.can1E {
				if err != nil {
					t.Fatalf("unexpected 1E code error: %v", err)
				}
				if code1e != tt.code1E {
					t.Errorf("expected 1E code 0x%02X, got 0x%02X", tt.code1E, code1e)
				}
			} else {
				if err == nil {
					t.Errorf("expected 1E code error for %s, got nil", dev.Name)
				}
			}
		})
	}
}
