package spear

import (
	"testing"
)

func recheck(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
