package main

import (
    "errors"
    "flag"
    "fmt"
    "os"
)

func parseArgs() (cipher string, encOrDec bool, fileIn, fileOut string) {

    var vigFlag, affineFlag, teaFlag, encFlag, decFlag bool

    flag.BoolVar(&vigFlag, "v", false, "Vigenere cipher")
    flag.BoolVar(&affineFlag, "a", false, "Affine cipher")
    flag.BoolVar(&teaFlag, "t", false, "TEA cipher")
    flag.BoolVar(&encFlag, "e", false, "Encrypt")
    flag.BoolVar(&decFlag, "d", false, "Decrypt")
    flag.Parse()

    if vigFlag {
        if affineFlag || teaFlag {
            exitError("Only one cipher can be used.")
        }
        cipher = "vigenere"
    } else if affineFlag {
        if teaFlag {
            exitError("Only one cipher can be used.")
        }
        cipher = "affine"
    } else if teaFlag {
        cipher = "tea"
    } else {
        exitError("No cipher declared.")
    }

    if encFlag && decFlag {
        exitError("Can only encrypt or decrypt, not both.")
    }

    if encFlag {
        encOrDec = true
    } else if decFlag {
        encOrDec = false
    } else {
        exitError("Must define if encryption or decryption.")
    }

    fileIn = flag.Arg(0)
    fileOut = flag.Arg(1)

    return
}

func readPPMFile(filename string) (int, int, int, []byte, error) {

    ppmFile, err := os.Open(filename)
    if err != nil {
        return 0, 0, 0, nil, err
    }
    defer ppmFile.Close()

    // scan the metadata and check its validity
    var width, height, maxColor int
    var magic string
    _, err = fmt.Fscan(ppmFile, &magic, &width, &height, &maxColor)
    if err != nil {
        return 0, 0, 0, nil, err
    }
    if magic != "P6" {
        return 0, 0, 0, nil, errors.New("File is not in PPM format.")
    }

    // scan the image bytes from the file
    dataSize := 3 * width * height
    image := make([]byte, dataSize)
    _, err = ppmFile.Read(image)

    return width, height, maxColor, image, err
}

func writePPMFile(filename string, encImage []byte, width, height, maxColor int) (err error) {

    ppmFile, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer ppmFile.Close()

    ppmContent := fmt.Sprintf("P6\n%d %d\n%d\n", width, height, maxColor)
    _, err = ppmFile.Write(append([]byte(ppmContent), encImage...))

    return
}

func readVigenereKey() (key []byte) {

    fmt.Print("Key size: ")

    var keySize int
    _, err := fmt.Scanf("%d", &keySize)
    checkError(err)

    key = make([]byte, keySize)

    fmt.Print("Encryption key: ")
    for i := 0; i < keySize; i++ {
        _, err = fmt.Scanf("%d", &key[i])
        checkError(err)
    }

    return
}

func readAffineParams() (affineA, affineB int) {

    fmt.Print("Enter parameter a: ")
    _, err := fmt.Scanf("%d", &affineA)
    checkError(err)

    fmt.Print("Enter parameter b: ")
    _, err = fmt.Scanf("%d", &affineB)
    checkError(err)

    if affineA < 0 || affineA > 255 || affineB < 0 || affineB > 255 {
        exitError("Numbers a and b should be between 0 and 255.\n")
    }
    if gcd(affineA, 256) != 1 {
        // exitError("First number a is not co-prime with 256.\n")
    }

    return
}

func readTeaKey() (key [4]uint32) {

    fmt.Print("Encryption key (4 hexadecimal): ")
    for i := 0; i < 4; i++ {
        _, err := fmt.Scan(&key[i])
        checkError(err)
        // _, err := fmt.Scanf("%s", hexString)
        // _, err := fmt.Scanf("%v %v %v %v", &key[0], &key[1], &key[2], &key[3])
        // checkError(err)
    }

    return
}
