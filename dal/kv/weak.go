package kv

import (
	"math"
	"math/rand"
	"time"

	"github.com/coyove/common/lru"
)

type weakEntry struct {
	data interface{}
	born time.Time
}

func WeakGet(weakCache *lru.Cache, k string) (interface{}, bool) {
	if v, ok := weakCache.Get(k); ok {
		e := v.(*weakEntry)
		if rand.Float64() <= 1.0/math.Log10(time.Since(e.born).Seconds()+1) {
			return e.data, true
		}
	}
	return nil, false
}

func WeakSet(weakCache *lru.Cache, k string, v interface{}) {
	weakCache.Add(k, &weakEntry{v, time.Now()})
}
