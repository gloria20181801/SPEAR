package spear

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func benchmarkIDRLSizes(t *testing.T) []int {
	t.Helper()
	s := os.Getenv("IDRL_SIZES")
	if s == "" {
		return []int{1, 4, 16, 64, 256, 1024, 4096, 16384}
	}
	values := []int{}
	seen := map[int]bool{}
	for _, word := range strings.Split(s, ",") {
		n, e := strconv.Atoi(word)
		if e != nil || n < 1 || n > 16384 || seen[n] {
			t.Fatal("IDRL_SIZES must be unique integers from 1 to 16384")
		}
		values = append(values, n)
		seen[n] = true
	}
	return values
}
