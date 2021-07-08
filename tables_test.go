package shamir

import (
	"testing"
)

func TestTables(t *testing.T) {
	for i := 1; i < 65536; i++ {
		logV := logTable[i]
		expV := expTable[logV]
		if expV != uint16(i) {
			t.Fatalf("bad: %d log: %d exp: %d", i, logV, expV)
		}
	}
}
