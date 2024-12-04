package middleware

import (
	"context"
	"runtime"
)

type MemoryStatsMiddleware struct {
	statsCollector StatsCollector
}

func NewMemoryStatsMiddleware(statsCollector StatsCollector) *MemoryStatsMiddleware {
	return &MemoryStatsMiddleware{statsCollector: statsCollector}
}

const memoryStatsDataKey = contextKey("memoryStatsData")

type memoryStatsData struct {
	startAlloc         uint64
	startHeapObjects   uint64
	startNumGC         uint32
	startPauseTotalNs  uint64
	startGCCPUFraction float64
}

func (m *MemoryStatsMiddleware) Before(ctx context.Context, methodName string, args []interface{}) context.Context {
	runtime.GC()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	data := &memoryStatsData{
		startAlloc:         memStats.Alloc,
		startHeapObjects:   memStats.HeapObjects,
		startNumGC:         memStats.NumGC,
		startPauseTotalNs:  memStats.PauseTotalNs,
		startGCCPUFraction: memStats.GCCPUFraction,
	}
	return context.WithValue(ctx, memoryStatsDataKey, data)
}

func (m *MemoryStatsMiddleware) After(ctx context.Context, methodName string, results []interface{}, err error) {
	data, ok := ctx.Value(memoryStatsDataKey).(*memoryStatsData)
	if !ok {
		return
	}
	runtime.GC()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	allocDiff := float64(memStats.Alloc-data.startAlloc) / (1024 * 1024)
	currentAllocMB := float64(memStats.Alloc) / (1024 * 1024)
	heapObjectsDiff := memStats.HeapObjects - data.startHeapObjects
	gcCycles := memStats.NumGC - data.startNumGC
	gcPauseNs := memStats.PauseTotalNs - data.startPauseTotalNs
	gcCPUFraction := memStats.GCCPUFraction - data.startGCCPUFraction

	stats := map[string]interface{}{
		"current_alloc_MB":  currentAllocMB,
		"alloc_diff_MB":     allocDiff,
		"heap_objects_diff": heapObjectsDiff,
		"gc_cycles":         gcCycles,
		"gc_pause_ns":       gcPauseNs,
		"gc_cpu_fraction":   gcCPUFraction,
	}
	m.statsCollector.Collect("MemoryStatsMiddleware", methodName, stats)
}
