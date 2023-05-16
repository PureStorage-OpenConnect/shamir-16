package shamir

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
)

const (
	// ShareOverhead is the byte size overhead of each share
	// when using Split on a secret. This is caused by appending
	// a word-long tag to the share.
	ShareOverhead = 2

	SizeGF16     = 65536
	ModuloGF16   = SizeGF16 - 1
	MaxPartsGF16 = SizeGF16 - 1
)

// polynomial represents a polynomial of arbitrary degree
type polynomial struct {
	coefficients []uint16
}

type Secret []byte
type Part []byte

func uint16ToByte(s []uint16) []byte {
	out := new(bytes.Buffer)
	err := binary.Write(out, binary.BigEndian, s)
	if err != nil {
		panic(err)
	}
	return out.Bytes()
}

func byteToUint16(s []byte) []uint16 {
	out := make([]uint16, len(s)/2)
	err := binary.Read(bytes.NewReader(s), binary.BigEndian, out)
	if err != nil {
		panic(err)
	}
	return out
}

// makePolynomial constructs a random polynomial of the given
// degree but with the provided intercept value.
func makePolynomial(intercept, degree uint16) (polynomial, error) {
	// Create a wrapper
	p := polynomial{
		coefficients: make([]uint16, 1),
	}

	// Ensure the intercept is set
	p.coefficients[0] = intercept

	// Assign random co-efficients to the polynomial
	coefficients8 := make([]byte, degree*2)
	if _, err := rand.Read(coefficients8); err != nil {
		return p, err
	}

	p.coefficients = append(p.coefficients, byteToUint16(coefficients8)...)

	return p, nil
}

// evaluate returns the value of the polynomial for the given x
func (p *polynomial) evaluate(x uint16) uint16 {
	// Special case the origin
	if x == 0 {
		return p.coefficients[0]
	}

	// Compute the polynomial value using Horner's method.
	degree := len(p.coefficients) - 1
	out := p.coefficients[degree]
	for i := degree - 1; i >= 0; i-- {
		coeff := p.coefficients[i]
		out = add(mult(out, x), coeff)
	}
	return out
}

// interpolatePolynomial takes N sample points and returns
// the value at a given x using a lagrange interpolation.
func interpolatePolynomial(x_samples, y_samples []uint16, x uint16) uint16 {
	limit := len(x_samples)
	var result, basis uint16
	for i := 0; i < limit; i++ {
		basis = 1
		for j := 0; j < limit; j++ {
			if i == j {
				continue
			}
			num := add(x, x_samples[j])
			denom := add(x_samples[i], x_samples[j])
			term := div(num, denom)
			basis = mult(basis, term)
		}
		group := mult(y_samples[i], basis)
		result = add(result, group)
	}
	return result
}

// div divides two numbers in GF(2^16)
func div(a, b uint16) uint16 {
	if b == 0 {
		// leaks some timing information but we don't care anyways as this
		// should never happen, hence the panic
		panic("divide by zero")
	}

	log_a := logTable[a]
	log_b := logTable[b]
	diff := ((int(log_a) - int(log_b)) + ModuloGF16) % ModuloGF16

	ret := int(expTable[diff])

	// Ensure we return zero if a is zero but aren't subject to timing attacks
	ret = subtle.ConstantTimeSelect(subtle.ConstantTimeEq(int32(a), 0), 0, ret)
	return uint16(ret)
}

// mult multiplies two numbers in GF(2^16)
func mult(a, b uint16) uint16 {
	log_a := logTable[a]
	log_b := logTable[b]
	sum := (int(log_a) + int(log_b)) % ModuloGF16

	ret := int(expTable[sum])

	// Ensure we return zero if either a or b are zero but aren't subject to
	// timing attacks
	ret = subtle.ConstantTimeSelect(subtle.ConstantTimeEq(int32(a), 0), 0, ret)
	ret = subtle.ConstantTimeSelect(subtle.ConstantTimeEq(int32(b), 0), 0, ret)

	return uint16(ret)
}

// add combines two numbers in GF(2^16)
// This can also be used for subtraction since it is symmetric.
func add(a, b uint16) uint16 {
	return a ^ b
}

// Split takes an arbitrarily long secret with even length and generates a `parts`
// number of shares, `threshold` of which are required to reconstruct
// the secret. The parts and threshold must be at least 2, and less
// than 'sizeGF16'. The returned shares are each one word longer than the secret
// as they attach a tag used to reconstruct the secret.
func Split(secret Secret, parts, threshold int) ([]Part, error) {
	// Cannot heve less parts than is the threshold
	if parts < threshold {
		return nil, fmt.Errorf("parts cannot be less than threshold")
	}
	// Cannot have more parts than is the limit for GF(2^16)
	if parts > MaxPartsGF16 {
		return nil, fmt.Errorf("parts cannot exceed %d", MaxPartsGF16)
	}
	// Threshold of 1 makes no sense
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	// Secret cannot be zero length
	if len(secret) == 0 {
		return nil, fmt.Errorf("cannot split an empty secret")
	}
	// Must be even length due to GF(2^16 representation)
	if len(secret)%2 != 0 {
		return nil, fmt.Errorf("cannot split odd length secret")
	}

	secret16 := byteToUint16(secret)

	// Allocate the output array, initialize the final word
	// of the output with the offset. The representation of each
	// output is {y1, y2, .., yN, x}.
	// See https://crypto.stackexchange.com/a/63490 for reasoning about x values
	out16 := make([][]uint16, parts)
	for idx := range out16 {
		out16[idx] = make([]uint16, len(secret16)+1)
		out16[idx][len(secret16)] = uint16(idx) + 1
	}

	// Construct a random polynomial for each word of the secret.
	// Because we are using a field of size 2^16, we can only represent
	// a 16bit word as the intercept of the polynomial, so we must
	// use a new polynomial for each 16bit word.
	for idx, val := range secret16 {
		p, err := makePolynomial(val, uint16(threshold-1))
		if err != nil {
			return nil, fmt.Errorf("failed to generate polynomial: %w", err)
		}

		// Generate a `parts` number of (x,y) pairs
		// We cheat by encoding the x value once as the final index,
		// so that it only needs to be stored once.
		for i := 0; i < parts; i++ {
			x := uint16(i) + 1
			y := p.evaluate(x)
			out16[i][idx] = y
		}
	}

	out := make([]Part, 0)
	for _, array16 := range out16 {
		out = append(out, uint16ToByte(array16))
	}

	// Return the encoded secrets
	return out, nil
}

// Combine is used to reverse a Split and reconstruct a secret
// once a `threshold` number of parts are available.
func Combine(parts []Part) (Secret, error) {
	// Verify enough parts provided
	if len(parts) < 2 {
		return nil, fmt.Errorf("less than two parts cannot be used to reconstruct the secret")
	}
	// Four bytes is the smallest Part possibly produced by Split()
	firstPartLen := len(parts[0])
	if firstPartLen < 4 {
		return nil, fmt.Errorf("parts must be at least four bytes")
	}
	// Must be even length due to GF(2^16 representation)
	if firstPartLen%2 == 1 {
		return nil, fmt.Errorf("parts must be even bytes long")
	}
	// Verify the parts are all the same length
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) != firstPartLen {
			return nil, fmt.Errorf("all parts must be the same length")
		}
	}

	parts16 := make([][]uint16, 0)
	for _, array8 := range parts {
		parts16 = append(parts16, byteToUint16(array8))
	}

	// Create a buffer to store the reconstructed secret
	secret16 := make([]uint16, len(parts16[0])-1)

	// Buffer to store the samples
	x_samples := make([]uint16, len(parts))

	// Set the x value for each sample and ensure no x_sample values are the same,
	// otherwise div() can be unhappy
	checkMap := make(map[uint16]struct{}, len(parts16))
	for i, part := range parts16 {
		samp := part[len(part)-1]
		if _, exists := checkMap[samp]; exists {
			return nil, fmt.Errorf("duplicate part detected")
		}
		checkMap[samp] = struct{}{}
		x_samples[i] = samp
	}

	queue := make(chan struct {
		int
		uint16
	})

	// Reconstruct each word
	for idx := range secret16 {

		// Compute every word of secret in separate goroutine.
		// Experimentally, this is about 2x as fast for GOMAXPROCS => 8,
		// with virtually no overhead if parallelization is not an option.
		go func(queue chan struct {
			int
			uint16
		}, parts16 [][]uint16, x_samples []uint16, idx int) {
			y_samples := make([]uint16, len(parts))

			// Set the y value for each sample
			for i, part := range parts16 {
				y_samples[i] = part[idx]
			}

			// Interpolate the polynomial and compute the value at 0
			val := interpolatePolynomial(x_samples, y_samples, 0)

			queue <- struct {
				int
				uint16
			}{idx, val}
		}(queue, parts16, x_samples, idx)
	}

	// Evaluate the 0th value to get the intercept
	for range secret16 {
		result := <-queue
		secret16[result.int] = result.uint16
	}

	return uint16ToByte(secret16), nil
}
