package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func measureStage(t *testing.T, name string, prepare func() func()) {
	for i := 0; i < 5; i++ {
		prepare()()
	}
	xs := make([]int64, 300)
	for i := range xs {
		fn := prepare()
		start := time.Now()
		fn()
		xs[i] = time.Since(start).Nanoseconds()
	}
	b, _ := json.Marshal(map[string]interface{}{"name": name, "samples_ns": xs})
	fmt.Println("BENCH " + string(b))
}
