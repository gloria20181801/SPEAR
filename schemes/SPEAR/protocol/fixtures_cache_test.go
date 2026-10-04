package spear

import (
	"testing"
)

func makeProverCache(t *testing.T, f *spearFixture) *SPEARProverCache {
	c, e := NewSPEARProverCache(f.params, f.audit, f.cred, &f.m1, &f.m2, &f.m, f.vk, &f.acc)
	recheck(t, e)
	return c
}

func cachedToken(t *testing.T, f *spearFixture, c *SPEARProverCache) *SPEARFullToken {
	h, e := c.Precompute(f.token(t), &f.digest)
	recheck(t, e)
	return h
}
