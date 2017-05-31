package main

import (
    "encoding/binary"
)

// byteArrayToUint32 receives a byte slice as parameter and its byte endianness
// in relation to 32-bit. It returns the converted 32-bit unsigned format.
func byteArrayToUint32(byteArr []byte, endianness binary.ByteOrder) (uint32Arr []uint32) {

    // append number 0 until byteArr length is a product of 4, so the array can
    // be fully converted from 8-bit elements to 32-bit elements
    for i:= 0; i < len(byteArr) % 4; i++ {
        byteArr = append(byteArr, byte(0))
    }

    uint32Len := len(byteArr) / 4
    uint32Arr = make([]uint32, uint32Len)

    // convert every 4 8-bit elements to 1 32-bit element
    for i := 0; i < uint32Len; i++ {
        uint32Arr[i] = endianness.Uint32(byteArr[i*4:i*4+4])
    }

    return
}

// byteArrayToUint64 receives a byte slice as parameter and its byte endianness
// in relation to 64-bit. It returns the converted 64-bit unsigned format.
func byteArrayToUint64(byteArr []byte, endianness binary.ByteOrder) (uint64Arr []uint64) {

    // append number 0 until byteArr length is a product of 8, so the array can
    // be fully converted from 8-bit elements to 64-bit elements
    for i:= 0; i < len(byteArr) % 8; i++ {
        byteArr = append(byteArr, byte(0))
    }

    uint64Len := len(byteArr) / 4
    uint64Arr = make([]uint64, uint64Len)

    // convert every 8 bytes to 1 64-bit element
    for i := 0; i < uint64Len; i++ {
        uint64Arr[i] = endianness.Uint64(byteArr[i*8:i*8+8])
    }

    return
}


func uint32SliceTo64(uint32Slice [2]uint32) (res uint64) {
    return uint64(uint32Slice[0]) << 32 + uint64(uint32Slice[1])
}

func uint64ToUint32Slice(x uint64) (uint32Slice [2]uint32) {
    uint32Slice[0] = uint32(x >> 32)
    uint32Slice[1] = uint32(x & 0x00000000ffffffff)
    return
}

// uint32ArrayToByte receives a uint32 slice as parameter and the byte
// endianness of its byte representation. It returns the converted byte array.
func uint32ArrayToByte(uint32Arr []uint32) (byteArr []byte) {

    byteLen := len(uint32Arr) * 4
    byteArr = make([]byte, byteLen)

    for i := 0; i < byteLen; i += 4 {
        binary.BigEndian.PutUint32(byteArr[i:i+4], uint32Arr[i/4])
    }

    return
}

// uint64ArrayToByte receives a uint64 slice as parameter and the byte
// endianness of its byte representation. It returns the converted byte array.
func uint64ArrayToByte(uint32Arr []uint64) (byteArr []byte) {

    byteLen := len(uint32Arr) * 8
    byteArr = make([]byte, byteLen)

    for i := 0; i < byteLen; i += 8 {
        binary.BigEndian.PutUint64(byteArr[i:i+8], uint32Arr[i/8])
    }

    return
}
