package sm3

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

// The size of a SM3 checksum in bytes.
const Size = 32

// The blocksize of SM3 in bytes.
const BlockSize = 64

const (
	chunk = 64
	init0 = 0x7380166F
	init1 = 0x4914B2B9
	init2 = 0x172442D7
	init3 = 0xDA8A0600
	init4 = 0xA96F30BC
	init5 = 0x163138AA
	init6 = 0xE38DEE4D
	init7 = 0xB0FB0E4E
)

type digest struct {
	h   [8]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

func (d *digest) Reset() {
	d.h[0] = init0
	d.h[1] = init1
	d.h[2] = init2
	d.h[3] = init3
	d.h[4] = init4
	d.h[5] = init5
	d.h[6] = init6
	d.h[7] = init7
	d.nx = 0
	d.len = 0
}

func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

func (d *digest) Size() int { return Size }

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d *digest) Sum(in []byte) []byte {
	// Make a copy of d so that caller can keep writing and summing.
	d0 := *d
	hash := d0.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() [Size]byte {
	len := d.len
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	binary.BigEndian.PutUint64(tmp[:], len)
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	var digest [Size]byte

	binary.BigEndian.PutUint32(digest[0:], d.h[0])
	binary.BigEndian.PutUint32(digest[4:], d.h[1])
	binary.BigEndian.PutUint32(digest[8:], d.h[2])
	binary.BigEndian.PutUint32(digest[12:], d.h[3])
	binary.BigEndian.PutUint32(digest[16:], d.h[4])
	binary.BigEndian.PutUint32(digest[20:], d.h[5])
	binary.BigEndian.PutUint32(digest[24:], d.h[6])
	binary.BigEndian.PutUint32(digest[28:], d.h[7])
	return digest
}

func p1(x uint32) uint32 { return x ^ bits.RotateLeft32(x, 15) ^ bits.RotateLeft32(x, 23) }

func block(dig *digest, p []byte) {

	var w [68]uint32

	A, B, C, D, E, F, G, H :=
		dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7]

	for len(p) >= chunk {

		//填充w的前16个字节
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = uint32(p[j])<<24 | uint32(p[j+1])<<16 | uint32(p[j+2])<<8 | uint32(p[j+3])
		}

		//填充w剩余的字节
		for i := 16; i < 68; i++ {
			w[i] = p1(w[i-16]^w[i-9]^bits.RotateLeft32(w[i-3], 15)) ^ bits.RotateLeft32(w[i-13], 7) ^ w[i-6]
		}

		//剩余64字节，在后面循环中在处理

		a, b, c, d, e, f, g, h := A, B, C, D, E, F, G, H

		for i := 0; i < 16; i++ {
			ss1 := bits.RotateLeft32(bits.RotateLeft32(a, 12)+e+bits.RotateLeft32(0x79CC4519, i), 7)
			ss2 := ss1 ^ bits.RotateLeft32(a, 12)
			wi := w[i] ^ w[i+4]
			tt1 := (a ^ b ^ c) + d + ss2 + wi
			tt2 := (e ^ f ^ g) + h + ss1 + w[i]
			d = c
			c = bits.RotateLeft32(b, 9)
			b = a
			a = tt1
			h = g
			g = bits.RotateLeft32(f, 19)
			f = e
			e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)
		}

		for i := 16; i < 64; i++ {
			ss1 := bits.RotateLeft32(bits.RotateLeft32(a, 12)+e+bits.RotateLeft32(0x7a879d8a, i), 7)
			ss2 := ss1 ^ bits.RotateLeft32(a, 12)
			wi := w[i] ^ w[i+4]
			tt1 := ((a & b) | (a & c) | (b & c)) + d + ss2 + wi
			tt2 := ((e & f) | (^e & g)) + h + ss1 + w[i]
			d = c
			c = bits.RotateLeft32(b, 9)
			b = a
			a = tt1
			h = g
			g = bits.RotateLeft32(f, 19)
			f = e
			e = tt2 ^ bits.RotateLeft32(tt2, 9) ^ bits.RotateLeft32(tt2, 17)
		}

		A ^= a
		B ^= b
		C ^= c
		D ^= d
		E ^= e
		F ^= f
		G ^= g
		H ^= h

		p = p[chunk:]
	}

	dig.h[0], dig.h[1], dig.h[2], dig.h[3], dig.h[4], dig.h[5], dig.h[6], dig.h[7] = A, B, C, D, E, F, G, H
}

func Sum(data []byte) [Size]byte {
	var d digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}
