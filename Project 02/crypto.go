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

// teaEnc performs the Tiny Encryption Algorithm
func teaEnc(image []byte, key [4]uint32, encOrDec bool, method bool) (imageByte []byte) {

    plainUint32 := byteArrayToUint32(image, binary.BigEndian)
    cipherUint32 := make([]uint32, 2 + len(plainUint32))
    var slice32 [2]uint32

    if method {
        // CFB initialization vector
        cipherUint32[0] = 0xFECDAB98
        cipherUint32[1] = 0x76543210
    } else {
        // ECB unused data
        cipherUint32[0] = 0x00000000
        cipherUint32[1] = 0x00000000
    }

    // encrypt/decrypt each pair of 32-bit elements using the TEA encryption
    for i := 0; i < len(plainUint32); i += 2 {

        if method {
            // Cipher feedback mode
            if encOrDec {
                slice32 = cfbEnc(plainUint32[i:i+2], cipherUint32[i:i+2], key)
            } else {
                slice32 = cfbDec(cipherUint32[i:i+4], key)
            }
        } else {
            // Electronic cookbook
            if encOrDec {
                slice32 = teaEncRounds([2]uint32{plainUint32[i],
                                                 plainUint32[i+1]},
                                       key)
            } else {
                slice32 = teaDecRounds([2]uint32{plainUint32[i],
                                                 plainUint32[i+1]},
                                       key)
            }
        }

        // updates the new resulted ciphertext
        cipherUint32[i+2] = slice32[0]
        cipherUint32[i+3] = slice32[1]
    }

    imageByte = uint32ArrayToByte(cipherUint32[2:])
    return
}


func cfbEnc(plain []uint32, cipher []uint32, key [4]uint32) ([2]uint32) {

    // encrypts the last ciphertext
    block64 := uint32SliceTo64([2]uint32{cipher[0], cipher[1]})
    slice32 := uint64ToUint32Slice(block64)

    slice32 = teaEncRounds(slice32, key)

    // xor the cipher result with the current plaintext
    plainSlice32 := [2]uint32{plain[0], plain[1]}
    block64 = uint32SliceTo64(plainSlice32) ^ uint32SliceTo64(slice32)
    slice32 = uint64ToUint32Slice(block64)

    return slice32
}

func cfbDec(plain []uint32, key [4]uint32) ([2]uint32) {

    prevPlain := [2]uint32{plain[0], plain[1]}
    currPlain := [2]uint32{plain[2], plain[3]}

    // encrypts the last plaintext
    block64 := uint32SliceTo64(prevPlain)
    slice32 := uint64ToUint32Slice(block64)

    slice32 = teaEncRounds(slice32, key)

    // xor the cipher result with the current plaintext
    block64 = uint32SliceTo64(currPlain) ^ uint32SliceTo64(slice32)
    slice32 = uint64ToUint32Slice(block64)

    return slice32
}

// teaEncRounds performs the encryption rounds of the TEA algorithm.
// It receives the 2 32-bit elements to be encrypted and a key with 4 elements.
// It returns the 2 decrypted elements.
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

// teaDecRounds performs the decryption rounds of the TEA algorithm.
// It receives the 2 32-bit elements to be decrypted and a key with 4 elements.
// It returns the 2 decrypted elements.
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
