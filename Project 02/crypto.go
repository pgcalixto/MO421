package main

import(
    "encoding/binary"
)

func vigenere(image, key []byte) (encImage []byte) {

    imageLen := len(image)
    encImage = make([]byte, imageLen)

    for i := 0; i < imageLen; i++ {
        encImage[i] = encImage[i] ^ key[i % imageLen];
    }
    return
}

func affineEnc(image []byte, affineA, affineB int) (encImage []byte) {

    imageLen := len(image)
    encImage = make([]byte, imageLen)

    byteA := byte(affineA)
    byteB := byte(affineB)

    for i := 0; i < imageLen; i++ {
        encImage[i] = byteA * image[i] + byteB
    }

    return
}

func affineDec(image []byte, affineA, affineB int) (decImage []byte) {

    imageLen := len(image)
    decImage = make([]byte, imageLen)

    aInv := modInverse(affineA, 256)
    byteAInv := byte(aInv)
    byteB := byte(affineB)

    for i := 0; i < imageLen; i++ {
        decImage[i] = byteAInv * (image[i] - byteB)
    }
    return
}

func teaEnc(image []byte, key [4]uint32, encOrDec bool) (resultImage []byte) {

    imageUint32 := byteArrayToUint32(image)
    var imageSlice [2]uint32

    // encrypt/decrypt each pair of 32-bit elements using the TEA encryption
    for i := 0; i < len(imageUint32); i += 2 {
        imageSlice[0] = imageUint32[i]
        imageSlice[1] = imageUint32[i+1]
        if encOrDec {
            imageSlice = teaEncRounds(imageSlice, key)
        } else {
            imageSlice = teaDecRounds(imageSlice, key)
        }
        imageUint32[i] = imageSlice[0]
        imageUint32[i+1] = imageSlice[1]
    }

    resultImage = uint32ArrayToByte(imageUint32)
    return
}

func teaEncRounds(image [2]uint32, key [4]uint32) ([2]uint32) {

    var y, z, sum, delta uint32

    y = image[0]
    z = image[1]
    sum = 0
    delta = 0x9E3779B9

    for i := 0; i < 32; i++ {
        sum += delta
        y += ((z << 4) + key[0]) ^ (z + sum) ^ ((z >> 5) + key[1])
        z += ((y << 4) + key[2]) ^ (y + sum) ^ ((y >> 5) + key[3])
    }

    return [2]uint32{y, z}
}

func teaDecRounds(image [2]uint32, key [4]uint32) ([2]uint32) {

    var y, z, sum, delta uint32

    y = image[0]
    z = image[1]
    // sum = 0xC6EF3720
    delta = 0x9E3779B9
    sum = delta << 5

    for i := 0; i < 32; i++ {
        z -= ((y << 4) + key[2]) ^ (y + sum) ^ ((y >> 5) + key[3])
        y -= ((z << 4) + key[0]) ^ (z + sum) ^ ((z >> 5) + key[1])
        sum -= delta
    }

    return [2]uint32{y, z}
}

func byteArrayToUint32(byteArr []byte) (uint32Arr []uint32) {

    // append number 0 until byteArr length is a product of 4, so the array can
    // be fully converted from 8-bit elements to 32-bit elements
    for i:= 0; i < len(byteArr) % 4; i++ {
        byteArr = append(byteArr, byte(0))
    }

    uint32Len := len(byteArr) / 4
    uint32Arr = make([]uint32, uint32Len)

    // convert every 4 8-bit elements to 1 32-bit element
    for i := 0; i < uint32Len; i++ {
        uint32Arr[i] = binary.BigEndian.Uint32(byteArr[i*4:i*4+4])
    }

    return
}

func uint32ArrayToByte(uint32Arr []uint32) (byteArr []byte) {

    byteLen := len(uint32Arr) * 4
    byteArr = make([]byte, byteLen)

    for i := 0; i < byteLen; i += 4 {
        binary.BigEndian.PutUint32(byteArr[i:i+4], uint32Arr[i/4])
    }

    return
}
