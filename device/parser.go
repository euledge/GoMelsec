package device

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseDevice は "D100", "X01A", "M100", "TS0", "ZR1000" などの文字列を Device 構造体に変換します。
func ParseDevice(raw string) (Device, error) {
	trimmed := strings.ToUpper(strings.TrimSpace(raw))
	if len(trimmed) < 2 {
		return Device{}, fmt.Errorf("%w: input too short: %q", ErrInvalidAddress, raw)
	}

	// 2文字プレフィックスのチェック
	if len(trimmed) >= 3 {
		prefix2 := trimmed[:2]
		numPart := trimmed[2:]
		switch prefix2 {
		case "SM":
			num, err := strconv.ParseUint(numPart, 10, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid SM address: %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevSM, Name: "SM", Number: uint32(num), IsBit: true, IsHex: false}, nil
		case "SD":
			num, err := strconv.ParseUint(numPart, 10, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid SD address: %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevSD, Name: "SD", Number: uint32(num), IsBit: false, IsHex: false}, nil
		case "TS":
			num, err := strconv.ParseUint(numPart, 10, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid TS address: %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevTS, Name: "TS", Number: uint32(num), IsBit: true, IsHex: false}, nil
		case "TC":
			num, err := strconv.ParseUint(numPart, 10, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid TC address: %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevTC, Name: "TC", Number: uint32(num), IsBit: true, IsHex: false}, nil
		case "TN":
			num, err := strconv.ParseUint(numPart, 10, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid TN address: %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevTN, Name: "TN", Number: uint32(num), IsBit: false, IsHex: false}, nil
		case "CS":
			num, err := strconv.ParseUint(numPart, 10, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid CS address: %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevCS, Name: "CS", Number: uint32(num), IsBit: true, IsHex: false}, nil
		case "CC":
			num, err := strconv.ParseUint(numPart, 10, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid CC address: %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevCC, Name: "CC", Number: uint32(num), IsBit: true, IsHex: false}, nil
		case "CN":
			num, err := strconv.ParseUint(numPart, 10, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid CN address: %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevCN, Name: "CN", Number: uint32(num), IsBit: false, IsHex: false}, nil
		case "SB":
			num, err := strconv.ParseUint(numPart, 16, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid SB address (hex expected): %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevSB, Name: "SB", Number: uint32(num), IsBit: true, IsHex: true}, nil
		case "SW":
			num, err := strconv.ParseUint(numPart, 16, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid SW address (hex expected): %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevSW, Name: "SW", Number: uint32(num), IsBit: false, IsHex: true}, nil
		case "DX":
			num, err := strconv.ParseUint(numPart, 16, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid DX address (hex expected): %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevDX, Name: "DX", Number: uint32(num), IsBit: true, IsHex: true}, nil
		case "DY":
			num, err := strconv.ParseUint(numPart, 16, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid DY address (hex expected): %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevDY, Name: "DY", Number: uint32(num), IsBit: true, IsHex: true}, nil
		case "ZR":
			// ZRは10進数または16進数（0x指定時）
			base := 10
			if strings.HasPrefix(numPart, "0X") {
				base = 16
				numPart = numPart[2:]
			}
			num, err := strconv.ParseUint(numPart, base, 32)
			if err != nil {
				return Device{}, fmt.Errorf("%w: invalid ZR address: %s", ErrInvalidAddress, numPart)
			}
			return Device{Type: DevZR, Name: "ZR", Number: uint32(num), IsBit: false, IsHex: base == 16}, nil
		}
	}

	// 1文字プレフィックスのチェック
	prefix1 := trimmed[:1]
	numPart := trimmed[1:]

	switch prefix1 {
	case "D":
		num, err := strconv.ParseUint(numPart, 10, 32)
		if err != nil {
			return Device{}, fmt.Errorf("%w: invalid D address: %s", ErrInvalidAddress, numPart)
		}
		return Device{Type: DevD, Name: "D", Number: uint32(num), IsBit: false, IsHex: false}, nil

	case "M":
		num, err := strconv.ParseUint(numPart, 10, 32)
		if err != nil {
			return Device{}, fmt.Errorf("%w: invalid M address: %s", ErrInvalidAddress, numPart)
		}
		return Device{Type: DevM, Name: "M", Number: uint32(num), IsBit: true, IsHex: false}, nil

	case "S":
		num, err := strconv.ParseUint(numPart, 10, 32)
		if err != nil {
			return Device{}, fmt.Errorf("%w: invalid S address: %s", ErrInvalidAddress, numPart)
		}
		return Device{Type: DevS, Name: "S", Number: uint32(num), IsBit: true, IsHex: false}, nil

	case "L":
		num, err := strconv.ParseUint(numPart, 10, 32)
		if err != nil {
			return Device{}, fmt.Errorf("%w: invalid L address: %s", ErrInvalidAddress, numPart)
		}
		return Device{Type: DevL, Name: "L", Number: uint32(num), IsBit: true, IsHex: false}, nil

	case "F":
		num, err := strconv.ParseUint(numPart, 10, 32)
		if err != nil {
			return Device{}, fmt.Errorf("%w: invalid F address: %s", ErrInvalidAddress, numPart)
		}
		return Device{Type: DevF, Name: "F", Number: uint32(num), IsBit: true, IsHex: false}, nil

	case "V":
		num, err := strconv.ParseUint(numPart, 10, 32)
		if err != nil {
			return Device{}, fmt.Errorf("%w: invalid V address: %s", ErrInvalidAddress, numPart)
		}
		return Device{Type: DevV, Name: "V", Number: uint32(num), IsBit: true, IsHex: false}, nil

	case "R":
		num, err := strconv.ParseUint(numPart, 10, 32)
		if err != nil {
			return Device{}, fmt.Errorf("%w: invalid R address: %s", ErrInvalidAddress, numPart)
		}
		return Device{Type: DevR, Name: "R", Number: uint32(num), IsBit: false, IsHex: false}, nil

	case "X":
		num, err := strconv.ParseUint(numPart, 16, 32)
		if err != nil {
			return Device{}, fmt.Errorf("%w: invalid X address (hex expected): %s", ErrInvalidAddress, numPart)
		}
		return Device{Type: DevX, Name: "X", Number: uint32(num), IsBit: true, IsHex: true}, nil

	case "Y":
		num, err := strconv.ParseUint(numPart, 16, 32)
		if err != nil {
			return Device{}, fmt.Errorf("%w: invalid Y address (hex expected): %s", ErrInvalidAddress, numPart)
		}
		return Device{Type: DevY, Name: "Y", Number: uint32(num), IsBit: true, IsHex: true}, nil

	case "W":
		num, err := strconv.ParseUint(numPart, 16, 32)
		if err != nil {
			return Device{}, fmt.Errorf("%w: invalid W address (hex expected): %s", ErrInvalidAddress, numPart)
		}
		return Device{Type: DevW, Name: "W", Number: uint32(num), IsBit: false, IsHex: true}, nil

	case "B":
		num, err := strconv.ParseUint(numPart, 16, 32)
		if err != nil {
			return Device{}, fmt.Errorf("%w: invalid B address (hex expected): %s", ErrInvalidAddress, numPart)
		}
		return Device{Type: DevB, Name: "B", Number: uint32(num), IsBit: true, IsHex: true}, nil

	default:
		return Device{}, fmt.Errorf("%w: unknown device prefix: %s", ErrInvalidAddress, raw)
	}
}
