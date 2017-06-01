package main

import (
    "fmt"
    "log"
)

func main() {

    // parse the arguments and checks their validity
    cipher, encOrDec, fileIn, fileOut := parseArgs()

    var resultImage []byte

    // open and read the PPM file
    width, height, maxColor, image, err := readPPMFile(fileIn)
    checkError(err)

    if cipher == "vigenere" {
        // performs vigenere cipher encryption/decryption
        key := readVigenereKey()
        if encOrDec {
            resultImage = vigenere(image, key)
        } else {
            resultImage = vigenere(image, key)
        }
    } else if cipher == "affine" {
        // performs affine encryption/decryption
        affineA, affineB := readAffineParams()
        if encOrDec {
            resultImage = affineEnc(image, affineA, affineB)
        } else {
            resultImage = affineDec(image, affineA, affineB)
        }
    } else if cipher == "tea" {
        // performs TEA encryption/decryption
        teaKey, opMode := readTeaParams()
        resultImage = teaEnc(image, teaKey, encOrDec, opMode)
    }

    err = writePPMFile(fileOut, resultImage, width, height, maxColor)
    checkError(err)

    fmt.Println()
}

// Exits the program with a Go raised error
func checkError(err error) {
    if err != nil {
        log.Fatal(err)
    }
}

// Exits the program with a custom usage messages and an error status
func raiseUsageError(msg string) {
    log.Fatal(msg + "\nusage: python3 affine_ppm.py [-v|-a|-t] [-e|-d] a b\n\n" +
              "  affine encryption: y = a*x + b  mod 256; 0 <= a,b <= 255")
}
