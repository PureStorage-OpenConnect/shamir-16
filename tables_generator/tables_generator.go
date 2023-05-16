// Simple code which creates Exponential and Logarithmic tables for fast GF(2^16) division and multiplication.
// The code can be easily checked for errors, or new polynomial can be used for the tables.
// Can be executed by simply calling 'go run tables_generator.go'

package main

import (
	"fmt"
	"os"

	"github.com/PureStorage-OpenConnect/shamir-16"
)

var placeholder_header string = `package shamir

// Tables generated tables_generator.go
// They use 'x^16 + x^12 + x^3 + x^1 + 1' or '0x100B' as the generator

var (`

var placeholder_logtable string = `
	// logTable provides the log(X)/log(g) at each index X
	logTable = [65536]uint16{
		`

var placeholder_exptable string = `}

	// expTable provides the anti-log or exponentiation value for the equivalent index
	expTable = [65536]uint16{
		`

var placeholder_footer string = `}
)
`

func multiplyGF16(a, b uint16) uint16 {
	// https://www.partow.net/programming/polynomials/index.html
	// x^16 + x^12 + x^3 + x^1 + 1
	// 10001000000001011
	// 0x100B

	var p, polynomial uint16

	polynomial = 0x100B
	p = 0

	for a > 0 && b > 0 {
		// If the rightmost bit of b is set, exclusive OR the product p by the value of a. This is polynomial addition.
		if b%2 == 1 {
			p ^= a
		}

		// Shift b one bit to the right, discarding the rightmost bit, and making the leftmost bit have a value of zero.
		// This divides the polynomial by x, discarding the x0 term.
		b >>= 1

		// Keep track of whether the leftmost bit of a is set to one and call this value carry.
		hasCarry := a > 0x7FFF

		// Shift a one bit to the left, discarding the leftmost bit, and making the new rightmost bit zero.
		// This multiplies the polynomial by x, but we still need to take account of carry which represented the coefficient of x7.
		a <<= 1

		// If carry had a value of one, exclusive or a with the irreducible polynomial with the high term eliminated.
		// Conceptually, the high term of the irreducible polynomial and carry add modulo 2 to 0.
		if hasCarry {
			a ^= polynomial
		}
	}

	return p
}

func tableGenerator() error {
	// Generator of multiplicative group, must represent an irreducible polynomial, tested for correctnes emipirically.
	const generator uint16 = 257
	var product uint16 = generator
	var err error

	expTable := make([]uint16, 0, shamir.SizeGF16)
	expTable = append(expTable, 1)
	expTable = append(expTable, product)
	count := 2 // Number of currently generated elements of multiplicative group

	logTable := make([]uint16, shamir.SizeGF16)
	logTable[product] = 1

	for product != 1 {
		product = multiplyGF16(generator, product)
		expTable = append(expTable, product)
		logTable[product] = uint16(count)
		count++
	}

	// Test that generator was correctly selected
	if count != shamir.SizeGF16 {
		_, err = os.Stderr.WriteString("Incorrectly selected generator! Please, select a different one and try again.")
		return err
	}

	fTables, err := os.Create("./../tables.go")
	defer fTables.Close()
	if err != nil {
		return err
	}

	_, err = fTables.WriteString(placeholder_header)
	if err != nil {
		return err
	}

	_, err = fTables.WriteString(placeholder_logtable)
	if err != nil {
		return err
	}

	lineLength := 16
	counter := 0
	for _, n := range logTable {
		_, err = fTables.WriteString(fmt.Sprintf("%#04x", n) + ", ")
		if err != nil {
			return err
		}
		counter++

		if counter%lineLength == 0 {
			_, err = fTables.WriteString("\n\t\t")
			if err != nil {
				return err
			}
		}
	}

	_, err = fTables.WriteString(placeholder_exptable)
	if err != nil {
		return err
	}

	counter = 0
	for _, n := range expTable {
		_, err = fTables.WriteString(fmt.Sprintf("%#04x", n) + ", ")
		if err != nil {
			return err
		}
		counter++

		if counter%lineLength == 0 {
			_, err = fTables.WriteString("\n\t\t")
			if err != nil {
				return err
			}
		}
	}

	_, err = fTables.WriteString(placeholder_footer)
	return err
}

func main() {
	err := tableGenerator()
	if err != nil {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
