package gomelsec

import (
	"errors"
	"gomelsec/device"
	"gomelsec/protocol"
	"gomelsec/transport"
)

var (
	ErrNotConnected         = transport.ErrNotConnected
	ErrTimeout              = transport.ErrTimeout
	ErrConnectionReset      = transport.ErrConnectionReset
	ErrInvalidAddress       = device.ErrInvalidAddress
	ErrUnsupportedDevice    = device.ErrUnsupportedDevice
	ErrPLCErrorResponse     = protocol.ErrPLCErrorResponse
	ErrResponseTooShort     = protocol.ErrResponseTooShort
	ErrInvalidSubHeader     = protocol.ErrInvalidSubHeader
	ErrSerialMismatch       = protocol.ErrSerialMismatch
	ErrUnsupportedOperation = protocol.ErrUnsupportedOperation

	ErrInvalidHexData = errors.New("invalid hexadecimal data string")
	ErrOddByteCount   = errors.New("byte count must be even for word operations")
)
