// Package mls implements the Messaging Layer Security protocol.
//
// MLS is specified in RFC 9420.
package mls

import (
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

func readVarint(s *cryptobyte.String, out *uint32) bool {
	var b uint8
	if !s.ReadUint8(&b) {
		return false
	}

	prefix := b >> 6
	if prefix == 3 {
		return false // invalid variable length integer prefix
	}

	n := 1 << prefix
	v := uint32(b & 0x3F)
	for i := 0; i < n-1; i++ {
		if !s.ReadUint8(&b) {
			return false
		}
		v = (v << 8) + uint32(b)
	}

	if prefix >= 1 && v < uint32(1)<<(8*(n/2)-2) {
		return false // minimum encoding was not used
	}

	*out = v
	return true
}

func writeVarint(b *cryptobyte.Builder, n uint32) {
	switch {
	case n < 1<<6:
		b.AddUint8(uint8(n))
	case n < 1<<14:
		b.AddUint16(0b01<<14 | uint16(n))
	case n < 1<<30:
		b.AddUint32(0b10<<30 | n)
	default:
		b.SetError(fmt.Errorf("mls: varint exceeds 30 bits"))
	}
}

func readOpaqueVec(s *cryptobyte.String, out *[]byte) bool {
	var n uint32
	if !readVarint(s, &n) {
		return false
	}

	b := make([]byte, n)
	if !s.CopyBytes(b) {
		return false
	}

	*out = b
	return true
}

func writeOpaqueVec(b *cryptobyte.Builder, value []byte) {
	if len(value) >= 1<<32 {
		b.SetError(fmt.Errorf("mls: opaque size exceeds maximum value of uint32"))
		return
	}
	writeVarint(b, uint32(len(value)))
	b.AddBytes(value)
}

func readVector(s *cryptobyte.String, f func(s *cryptobyte.String) error) error {
	var n uint32
	if !readVarint(s, &n) {
		return io.ErrUnexpectedEOF
	}
	var vec []byte
	if !s.ReadBytes(&vec, int(n)) {
		return io.ErrUnexpectedEOF
	}
	ss := cryptobyte.String(vec)
	for !ss.Empty() {
		if err := f(&ss); err != nil {
			return err
		}
	}
	return nil
}

func readOptional(s *cryptobyte.String, present *bool) bool {
	var u8 uint8
	if !s.ReadUint8(&u8) {
		return false
	}
	switch u8 {
	case 0:
		*present = false
	case 1:
		*present = true
	default:
		return false
	}
	return true
}
