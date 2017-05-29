package main

// obtain the modular inverse using the extended Euclides algorithm
func modInverse(a, b int) int {
    _, inv, _ := extendedEuclid(a, b)
    if inv < 0 {
        inv += b
    }
    return inv
}

// extended Euclides algorithm
func extendedEuclid(a, b int) (int, int, int) {
    if a == 0 {
        return b, 0, 1
    }

    g, x, y := extendedEuclid(b % a, a)
    return g, y - (b / a) * x, x
}

// Euclides algorithm to find gcd of two positive integers
func gcd(x, y int) int {
    for y != 0 {
        x, y = y, x%y
    }
    return x
}
