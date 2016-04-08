package pkcs11

import (
	"encoding/binary"
	"unsafe"
)

var native binary.ByteOrder

func init() {
	x := uint32(0x01020304)
	switch *(*byte)(unsafe.Pointer(&x)) {
	case 0x01:
		native = binary.BigEndian
	case 0x04:
		native = binary.LittleEndian
	}
}

func btoi(v []byte) uint {
	switch len(v) {
	case 1:
		return uint(v[0])
	case 2:
		return uint(native.Uint16(v))
	case 4:
		return uint(native.Uint32(v))
	case 8:
		return uint(native.Uint64(v))
	default:
		panic("bad int size")
	}
}
