package main

import(
    "encoding/binary"
)

// Performs the Vigenere cipher. It receives the plaintext and the key as byte arrays
// and returns the ciphertext byte array.
func vigenere(image, key []byte) (encImage []byte) {

    imageLen := len(image)
    keyLen := len(key)
    encImage = make([]byte, imageLen)

    for i := 0; i < imageLen; i++ {
        encImage[i] = image[i] ^ key[i % keyLen];
    }
    return
}

// Performs the affine cipher encryption. It receives the plaintext as byte array and
// the A and B keys, and returns the ciphertext byte array.
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

// Performs the affine cipher decryption. It receives the ciphertext as byte array and
// the A and B keys, and returns the plaintext byte array.
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

// teaEnc performs the Tiny Encryption Algorithm.
// image: byte array containing the plaintext/ciphertext to encrypt/decrypt.
// key: key used to perform encryption/decryption.
// encOrDec: encryption if true, decryption otherwise.
// opMode: block operation mode. CFB is true, ECB otherwise.
// Returns the ciphertext byte array.
func teaEnc(input []byte, key [4]uint32, encOrDec bool, opMode bool) (output []byte) {

    inputUint32 := byteArrayToUint32(input, binary.BigEndian)
    lenInputUint32 := len(inputUint32)
    outputUint32 := make([]uint32, 2 + len(inputUint32))
    var slice32 [2]uint32

    if opMode {
        if encOrDec {
            // CFB initialization vector
            outputUint32[0] = 0xFECDAB98
            outputUint32[1] = 0x76543210
        } else {
            // prepends the IV to the ciphertext input
            inputCopy := make([]uint32, 2 + len(inputUint32))
            copy(inputCopy[2:], inputUint32)
            inputCopy[0] = 0xFECDAB98
            inputCopy[1] = 0x76543210
            inputUint32 = inputCopy
        }
    } else {
        // ECB unused data
        outputUint32[0] = 0x00000000
        outputUint32[1] = 0x00000000
    }

    // encrypt/decrypt each pair of 32-bit elements using the TEA encryption
    for i := 0; i < lenInputUint32; i += 2 {

        if opMode {
            // CFB: Cipher feedback mode
            if encOrDec {
                slice32 = cfbEnc(inputUint32[i:i+2], outputUint32[i:i+2], key)
            } else {
                slice32 = cfbDec(inputUint32[i:i+4], key)
            }
        } else {
            // ECB: Electronic cookbook
            if encOrDec {
                slice32 = teaEncRounds([2]uint32{inputUint32[i],
                                                 inputUint32[i+1]},
                                       key)
            } else {
                slice32 = teaDecRounds([2]uint32{inputUint32[i],
                                                 inputUint32[i+1]},
                                       key)
            }
        }

        // updates the new resulted plaintext/ciphertext
        outputUint32[i+2] = slice32[0]
        outputUint32[i+3] = slice32[1]
    }

    output = uint32ArrayToByte(outputUint32[2:])
    return
}

// Encrypts that round using CFB. It receives the current plaintext and ciphertext and
// the key, and returns the new ciphertext.
func cfbEnc(plaintext []uint32, ciphertext []uint32, key [4]uint32) ([2]uint32) {

    // encrypts the last ciphertext
    // block64 := uint32SliceTo64([2]uint32{ciphertext[0], ciphertext[1]})
    // slice32 := uint64ToUint32Slice(block64)
    slice32 := [2]uint32{ciphertext[0], ciphertext[1]}

    slice32 = teaEncRounds(slice32, key)

    // xor the cipher result with the current plaintext
    plaintextSlice32 := [2]uint32{plaintext[0], plaintext[1]}
    // block64 = uint32SliceTo64(plaintextSlice32) ^ uint32SliceTo64(slice32)
    // slice32 = uint64ToUint32Slice(block64)
    slice32[0] = slice32[0] ^ plaintextSlice32[0]
    slice32[1] = slice32[1] ^ plaintextSlice32[1]

    return slice32
}

// Decrypts that round using CFB. It receives the previous and the current ciphertext
// and the key, and returns the new plaintext.
func cfbDec(ciphertext []uint32, key [4]uint32) ([2]uint32) {

    prevCiphertext := [2]uint32{ciphertext[0], ciphertext[1]}
    currCiphertext := [2]uint32{ciphertext[2], ciphertext[3]}

    // decrypts the last plaintext
    // block64 := uint32SliceTo64(prevCiphertext)
    // slice32 := uint64ToUint32Slice(block64)
    slice32 := prevCiphertext

    slice32 = teaEncRounds(slice32, key)

    // xor the cipher result with the current ciphertext
    // block64 = uint32SliceTo64(currCiphertext) ^ uint32SliceTo64(slice32)
    // slice32 = uint64ToUint32Slice(block64)
    slice32[0] = slice32[0] ^ currCiphertext[0]
    slice32[1] = slice32[1] ^ currCiphertext[1]

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
    delta = 0x9E3779B9
    sum = delta << 5

    for i := 0; i < 32; i++ {
        z -= ((y << 4) + key[2]) ^ (y + sum) ^ ((y >> 5) + key[3])
        y -= ((z << 4) + key[0]) ^ (z + sum) ^ ((z >> 5) + key[1])
        sum -= delta
    }

    return [2]uint32{y, z}
}
