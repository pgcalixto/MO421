package main

import (
    "fmt"
    "log"
)

func main() {

    // parse the arguments and checks their validity
    cipher, encOrDec, fileIn, fileOut := parseArgs()

    var vigKey []byte
    var affineA, affineB int
    var teaKey [4]uint32
    var resultImage []byte

    // open and read the PPM file
    width, height, maxColor, image, err := readPPMFile(fileIn)
    checkError(err)

    fmt.Println(width, height, maxColor, err)
    fmt.Println(len(image))


    if cipher == "vigenere" {
        // performs vigenere cipher encryption/decryption
        // note: vigenere uses the same algorithm for encryption and decryption
        vigKey = readVigenereKey()
        if encOrDec {
            resultImage = vigenere(image, vigKey)
        } else {
            resultImage = vigenere(image, vigKey)
        }
    } else if cipher == "affine" {
        // performs affine encryption/decryption
        affineA, affineB = readAffineParams()
        if encOrDec {
            resultImage = affineEnc(image, affineA, affineB)
        } else {
            resultImage = affineDec(image, affineA, affineB)
        }
    } else if cipher == "tea" {
        // performs TEA encryption/decryption
        teaKey = readTeaKey()
        resultImage = teaEnc(image, teaKey, encOrDec)
    }

    encImage := teaEnc(image, teaKey, true)
    decImage := teaEnc(encImage, teaKey, false)

    err = writePPMFile(fileOut, resultImage, width, height, maxColor)
    checkError(err)
}

func checkError(err error) {
    if err != nil {
        log.Fatal(err)
        // panic(err)
    }
}

// Exit the program with error and usage messages
func exitError(msg string) {
    log.Fatal(msg + "\nusage: python3 affine_ppm.py [-v|-a|-t] [-e|-d] a b\n\n" +
              "  affine encryption: y = a*x + b  mod 256; 0 <= a,b <= 255")
}
