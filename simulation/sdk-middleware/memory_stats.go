package middleware

import (
	"context"
	"runtime"
	"time"
)

type MemoryStatsMiddleware struct {
	statsCollector StatsCollector
	sampleInterval time.Duration
}

func NewMemoryStatsMiddleware(statsCollector StatsCollector) *MemoryStatsMiddleware {
	return &MemoryStatsMiddleware{statsCollector: statsCollector, sampleInterval: sampleInterval}
}

const memoryStatsDataKey = contextKey("memoryStatsData")

type memSample struct {
	time        time.Time // Timestamp when the sample was taken
	alloc       uint64    // Bytes of allocated heap memory at the sample time
	heapObjects uint64    // Number of allocated heap objects at the sample time
}

type memoryStatsData struct {
	startAlloc         uint64  // Initial heap allocation (in bytes) at start
	startHeapObjects   uint64  // Initial number of heap objects at start
	startNumGC         uint32  // Initial count of completed GC cycles at start
	startPauseTotalNs  uint64  // Initial total GC pause time (in nanoseconds) at start
	startGCCPUFraction float64 // Initial fraction of CPU time spent in GC at start

	cancelFunc func()      // Function to stop the periodic sampling goroutine
	memSamples []memSample // Collected memory usage samples over time
	startTime  time.Time   // Time when measurement began
}

func (m *MemoryStatsMiddleware) Before(ctx context.Context, methodName string, args []interface{}) context.Context {
	// Perform a garbage collection before measuring for consistent data
	runtime.GC()

	var memStats runtime.MemStats
	// Read initial memory statistics
	runtime.ReadMemStats(&memStats)
	data := &memoryStatsData{
		startAlloc:         memStats.Alloc,
		startHeapObjects:   memStats.HeapObjects,
		startNumGC:         memStats.NumGC,
		startPauseTotalNs:  memStats.PauseTotalNs,
		startGCCPUFraction: memStats.GCCPUFraction,
		startTime:          time.Now(),
		memSamples:         []memSample{},
	}

	// Create a cancellable context for periodic sampling
	sampleCtx, cancel := context.WithCancel(ctx)
	data.cancelFunc = cancel

	// Start a goroutine to periodically sample memory usage
	go func() {
		ticker := time.NewTicker(m.sampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Perform GC to provide a somewhat stable baseline for memory measurement
				runtime.GC()
				runtime.ReadMemStats(&memStats)
				data.memSamples = append(data.memSamples, memSample{
					time:        time.Now(),
					alloc:       memStats.Alloc,
					heapObjects: memStats.HeapObjects,
				})
			case <-sampleCtx.Done():
				// Stop sampling when the method execution ends
				return
			}
		}
	}()

	return context.WithValue(ctx, memoryStatsDataKey, data)
}

func (m *MemoryStatsMiddleware) After(ctx context.Context, methodName string, results []interface{}, err error) {
	data, ok := ctx.Value(memoryStatsDataKey).(*memoryStatsData)
	if !ok {
		return
	}

	// Stop the periodic sampling
	data.cancelFunc()

	// Perform a final GC and read final memory stats
	runtime.GC()
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// allocDiff: How many MB of additional memory were allocated compared to the start
	allocDiff := float64(memStats.Alloc-data.startAlloc) / (1024 * 1024)
	// currentAllocMB: Current heap allocation in MB at the end of the method
	currentAllocMB := float64(memStats.Alloc) / (1024 * 1024)
	// heapObjectsDiff: How many heap objects differ between start and end
	heapObjectsDiff := memStats.HeapObjects - data.startHeapObjects

	// Calculate peak and average allocations from the samples
	var totalAlloc float64
	var maxAlloc uint64
	for _, s := range data.memSamples {
		if s.alloc > maxAlloc {
			maxAlloc = s.alloc
		}
		totalAlloc += float64(s.alloc)
	}

	// avgAllocMB: Average heap allocation (MB) across all collected samples
	var avgAllocMB float64
	if len(data.memSamples) > 0 {
		avgAllocMB = (totalAlloc / float64(len(data.memSamples))) / (1024 * 1024)
	}

	// gcCycles: How many GC cycles occurred during method execution
	gcCycles := memStats.NumGC - data.startNumGC
	// gcPauseNs: Additional GC pause time accumulated during method execution
	gcPauseNs := memStats.PauseTotalNs - data.startPauseTotalNs
	// gcCPUFraction: Additional fraction of CPU time spent in GC since start
	gcCPUFraction := memStats.GCCPUFraction - data.startGCCPUFraction

	stats := map[string]interface{}{
		"current_alloc_MB":  currentAllocMB,                    // Current memory allocation at end of method in MB
		"peak_alloc_MB":     float64(maxAlloc) / (1024 * 1024), // Peak observed allocation in MB during execution
		"avg_alloc_MB":      avgAllocMB,                        // Average allocation in MB over samples
		"alloc_diff_MB":     allocDiff,                         // Difference in MB from start to end
		"heap_objects_diff": heapObjectsDiff,                   // Difference in count of heap objects from start to end
		"gc_cycles":         gcCycles,                          // Number of GC cycles that occurred
		"gc_pause_ns":       gcPauseNs,                         // Additional GC pause time in nanoseconds
		"gc_cpu_fraction":   gcCPUFraction,                     // Increase in fraction of CPU time spent in GC
	}
	m.statsCollector.Collect("MemoryStatsMiddleware", methodName, stats)
}
