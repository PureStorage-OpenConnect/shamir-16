package shamir

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestSplit_invalid(t *testing.T) {
	secret := Secret("test")

	if _, err := Split(secret, 0, 0); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := Split(secret, 2, 3); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := Split(secret, 1000000, 3); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := Split(secret, 10, 1); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := Split(nil, 3, 2); err == nil {
		t.Fatalf("expect error")
	}

	secret_short := Secret("tes")
	if _, err := Split(secret_short, 2, 2); err == nil {
		t.Fatalf("expect error")
	}
}

func TestSplit(t *testing.T) {
	secret := Secret("test")

	out, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if len(out) != 5 {
		t.Fatalf("bad: %v", out)
	}

	for _, share := range out {
		if len(share) != len(secret)+2 {
			t.Fatalf("bad: %v", out)
		}
	}
}

func TestCombine_invalid(t *testing.T) {
	// Not enough parts
	if _, err := Combine(nil); err == nil {
		t.Fatalf("should err")
	}

	// Mis-match in length
	parts := []Part{
		Part("foofoofoofoo"),
		Part("barbar"),
	}
	if _, err := Combine(parts); err == nil {
		t.Fatalf("should err")
	}

	// Too short
	parts = []Part{
		Part("fo"),
		Part("ba"),
	}
	if _, err := Combine(parts); err == nil {
		t.Fatalf("should err")
	}

	// Even Length
	parts = []Part{
		Part("foofo"),
		Part("bazba"),
	}
	if _, err := Combine(parts); err == nil {
		t.Fatalf("should err")
	}

	// Identic parts
	parts = []Part{
		Part("foof"),
		Part("foof"),
	}
	if _, err := Combine(parts); err == nil {
		t.Fatalf("should err")
	}
}

func TestCombine(t *testing.T) {
	secret := Secret("test")

	out, err := Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// There is 5*4*3 possible choices,
	// we will just brute force try them all
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			if j == i {
				continue
			}
			for k := 0; k < 5; k++ {
				if k == i || k == j {
					continue
				}
				parts := []Part{out[i], out[j], out[k]}
				recomb, err := Combine(parts)
				if err != nil {
					t.Fatalf("err: %v", err)
				}

				if !bytes.Equal(recomb, secret) {
					t.Errorf("parts: (i:%d, j:%d, k:%d) %v", i, j, k, parts)
					t.Fatalf("bad: %v %v", recomb, secret)
				}
			}
		}
	}
}

func TestSplitCombine(t *testing.T) {
	// use SHA256 to create random-looking deterministic secret
	secret := sha256.Sum256(Secret("key"))
	parts := 500
	threshold := parts / 2

	out, err := Split(secret[:], parts, threshold)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Expect wrong result below threshold
	recomb, err := Combine(out[:threshold-1])
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if bytes.Equal(recomb, secret[:]) {
		t.Fatalf("unexpected: %v %v", recomb, secret)
	}

	// Expect correct result at threshold
	recomb, err = Combine(out[:threshold])
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !bytes.Equal(recomb, secret[:]) {
		t.Fatalf("bad: %v %v", recomb, secret)
	}
}

func benchmarkShamir(parts int, b *testing.B) {
	for n := 0; n < b.N; n++ {
		// use SHA256 to create random-looking deterministic secret
		secret := sha256.Sum256(Secret("key"))
		threshold := parts / 2

		out, _ := Split(secret[:], parts, threshold)
		_, _ = Combine(out)
	}
}

func BenchmarkShamir10(b *testing.B) {
	benchmarkShamir(10, b)
}
func BenchmarkShamir20(b *testing.B) {
	benchmarkShamir(20, b)
}
func BenchmarkShamir50(b *testing.B) {
	benchmarkShamir(50, b)
}
func BenchmarkShamir100(b *testing.B) {
	benchmarkShamir(100, b)
}
func BenchmarkShamir200(b *testing.B) {
	benchmarkShamir(200, b)
}
func BenchmarkShamir500(b *testing.B) {
	benchmarkShamir(500, b)
}
func BenchmarkShamir1000(b *testing.B) {
	benchmarkShamir(1000, b)
}
func BenchmarkShamir2000(b *testing.B) {
	benchmarkShamir(2000, b)
}
func BenchmarkShamir5000(b *testing.B) {
	benchmarkShamir(5000, b)
}
func BenchmarkShamir10000(b *testing.B) {
	benchmarkShamir(10000, b)
}

func TestField_Add(t *testing.T) {
	if out := add(16, 16); out != 0 {
		t.Fatalf("Bad: %v 16", out)
	}

	if out := add(3, 4); out != 7 {
		t.Fatalf("Bad: %v 7", out)
	}
}

func TestField_Mult(t *testing.T) {
	if out := mult(3, 7); out != 9 {
		t.Fatalf("Bad: %v 9", out)
	}

	if out := mult(3, 0); out != 0 {
		t.Fatalf("Bad: %v 0", out)
	}

	if out := mult(0, 3); out != 0 {
		t.Fatalf("Bad: %v 0", out)
	}
}

func TestField_Divide(t *testing.T) {
	if out := div(0, 7); out != 0 {
		t.Fatalf("Bad: %v 0", out)
	}

	if out := div(3, 3); out != 1 {
		t.Fatalf("Bad: %v 1", out)
	}

	if out := div(6, 3); out != 2 {
		t.Fatalf("Bad: %v 2", out)
	}
}

func TestField_Divide_Zero(t *testing.T) {

	// If panicked correctly, recover() will be called, otherwise the error is printed

	defer func() { recover() }()
	div(1, 0)
	t.Errorf("Should have panicked")
}

func TestPolynomial_Zero(t *testing.T) {
	_, err := makePolynomial(42, 0)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestPolynomial_Random(t *testing.T) {
	p, err := makePolynomial(42, 2)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if p.coefficients[0] != 42 {
		t.Fatalf("bad: %v", p.coefficients)
	}
}

func TestPolynomial_Eval(t *testing.T) {
	p, err := makePolynomial(42, 1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if out := p.evaluate(0); out != 42 {
		t.Fatalf("bad: %v", out)
	}

	out := p.evaluate(1)
	exp := add(42, mult(1, p.coefficients[1]))
	if out != exp {
		t.Fatalf("bad: %v %v %v", out, exp, p.coefficients)
	}
}

func TestInterpolate_Rand(t *testing.T) {
	for i := 0; i < 65536; i++ {
		p, err := makePolynomial(uint16(i), 2)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		x_vals := []uint16{1, 2, 3}
		y_vals := []uint16{p.evaluate(1), p.evaluate(2), p.evaluate(3)}
		out := interpolatePolynomial(x_vals, y_vals, 0)
		if out != uint16(i) {
			t.Fatalf("Bad: %v %d", out, i)
		}
	}
}
