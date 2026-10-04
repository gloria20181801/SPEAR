package main

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

type roleClock struct {
	role  string
	start time.Time
	tot   map[string]int64
}

func newRoleClock(r string) *roleClock { return &roleClock{r, time.Now(), map[string]int64{}} }

func (c *roleClock) next(r string) {
	now := time.Now()
	c.tot[c.role] += now.Sub(c.start).Nanoseconds()
	c.role = r
	c.start = time.Now()
}

func (c *roleClock) done() map[string]int64 { c.next("done"); return c.tot }

func measureRoles(t *testing.T, name string, prepare func() func() map[string]int64) {
	for i := 0; i < 5; i++ {
		prepare()()
	}
	all := map[string][]int64{}
	for i := 0; i < 300; i++ {
		for role, ns := range prepare()() {
			all[role] = append(all[role], ns)
		}
	}
	for role, x := range all {
		b, _ := json.Marshal(map[string]interface{}{"name": name + "_" + role, "samples_ns": x})
		fmt.Println("BENCH " + string(b))
	}
}
