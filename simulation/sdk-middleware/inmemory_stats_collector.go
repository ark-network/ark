package middleware

import (
	"sync"
	"time"
)

type InMemoryStatsCollector struct {
	sync.Mutex
	Stats map[string]map[string][]map[string]interface{}
}

func NewInMemoryStatsCollector() *InMemoryStatsCollector {
	return &InMemoryStatsCollector{
		Stats: make(map[string]map[string][]map[string]interface{}),
	}
}

func (c *InMemoryStatsCollector) Collect(middlewareName string, methodName string, stats map[string]interface{}) {
	c.Lock()
	defer c.Unlock()

	stats["timestamp"] = time.Now()

	if _, ok := c.Stats[middlewareName]; !ok {
		c.Stats[middlewareName] = make(map[string][]map[string]interface{})
	}

	c.Stats[middlewareName][methodName] = append(c.Stats[middlewareName][methodName], stats)
}
