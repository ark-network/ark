package middleware

import (
	"context"
	log "github.com/sirupsen/logrus"
	"syscall"
	"time"
)

const sampleInterval = 200 * time.Millisecond

type CPUUtilizationMiddleware struct {
	statsCollector StatsCollector
	sampleInterval time.Duration
}

func NewCPUUtilizationMiddleware(statsCollector StatsCollector) *CPUUtilizationMiddleware {
	return &CPUUtilizationMiddleware{statsCollector: statsCollector, sampleInterval: sampleInterval}
}

const cpuUtilizationDataKey = contextKey("cpuUtilizationData")

type cpuSample struct {
	time     time.Time // The timestamp when the sample was taken
	userTime float64   // The amount of CPU time spent in user space since the start of the measurement
	sysTime  float64   // The amount of CPU time spent in system (kernel) space since the start
	cpuPct   float64   // The percentage of CPU utilization at this sample point
}

type cpuUtilizationData struct {
	startRusage syscall.Rusage // The initial resource usage snapshot at the beginning
	startTime   time.Time      // The time when we started measuring

	cancelFunc func()      // A function to cancel the periodic sampling goroutine
	samples    []cpuSample // Collected samples of CPU usage over time
}

func (m *CPUUtilizationMiddleware) Before(ctx context.Context, methodName string, args []interface{}) context.Context {
	var startRusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &startRusage); err != nil {
		log.Warnf("Failed to get rusage: %v", err)
	}
	startTime := time.Now()
	data := &cpuUtilizationData{
		startRusage: startRusage,
		startTime:   startTime,
		samples:     []cpuSample{},
	}

	// Create a cancellable context so we can stop sampling when the method finishes
	sampleCtx, cancel := context.WithCancel(ctx)
	data.cancelFunc = cancel

	// Periodically sample CPU usage in a separate goroutine
	go func() {
		ticker := time.NewTicker(m.sampleInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Take a new CPU usage snapshot at each interval
				var r syscall.Rusage
				syscall.Getrusage(syscall.RUSAGE_SELF, &r)
				elapsed := time.Since(data.startTime).Seconds()
				userTime := timeval2float64(r.Utime) - timeval2float64(data.startRusage.Utime)
				sysTime := timeval2float64(r.Stime) - timeval2float64(data.startRusage.Stime)
				totalCPU := userTime + sysTime
				cpuPct := (totalCPU / elapsed) * 100

				// Store the sample
				data.samples = append(data.samples, cpuSample{
					time:     time.Now(),
					userTime: userTime,
					sysTime:  sysTime,
					cpuPct:   cpuPct,
				})
			case <-sampleCtx.Done():
				// Stop sampling when the method execution completes
				return
			}
		}
	}()

	return context.WithValue(ctx, cpuUtilizationDataKey, data)
}

func (m *CPUUtilizationMiddleware) After(ctx context.Context, methodName string, results []interface{}, err error) {
	data, ok := ctx.Value(cpuUtilizationDataKey).(*cpuUtilizationData)
	if !ok {
		return
	}
	// Stop periodic sampling
	data.cancelFunc()

	var endRusage syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &endRusage)

	duration := time.Since(data.startTime)

	// userTimeDiff: total user-mode CPU time used by the process during the method execution
	userTimeDiff := timeval2float64(endRusage.Utime) - timeval2float64(data.startRusage.Utime)
	// sysTimeDiff: total system-mode CPU time used by the process during the method execution
	sysTimeDiff := timeval2float64(endRusage.Stime) - timeval2float64(data.startRusage.Stime)
	// totalCPUTime: sum of user and system time, representing total CPU time consumed
	totalCPUTime := userTimeDiff + sysTimeDiff
	// cpuPercentage: overall CPU usage percentage (avg) over the entire duration
	cpuPercentage := (totalCPUTime / duration.Seconds()) * 100

	// Calculate peak and average CPU usage from collected samples
	var maxCPU float64
	var totalCPU float64
	for _, s := range data.samples {
		// maxCPU: the highest recorded CPU percentage from the periodic samples
		if s.cpuPct > maxCPU {
			maxCPU = s.cpuPct
		}
		// Accumulate total CPU percentages for averaging
		totalCPU += s.cpuPct
	}

	// avgCPU: average CPU percentage over all samples collected
	var avgCPU float64
	if len(data.samples) > 0 {
		avgCPU = totalCPU / float64(len(data.samples))
	}

	// Stats collected:
	stats := map[string]interface{}{
		"duration_seconds":    duration.Seconds(), // How long the method took to execute in seconds
		"cpu_percentage":      cpuPercentage,      // Average CPU usage over the entire method execution
		"cpu_percentage_peak": maxCPU,             // The highest CPU usage observed during any sample
		"cpu_percentage_avg":  avgCPU,             // The average CPU usage across all sampled intervals
		"user_time_seconds":   userTimeDiff,       // Total user-mode CPU time spent
		"system_time_seconds": sysTimeDiff,        // Total system-mode CPU time spent
		"total_cpu_time":      totalCPUTime,       // Total CPU time (user + system) spent
	}

	m.statsCollector.Collect("CPUUtilizationMiddleware", methodName, stats)
}

func timeval2float64(tv syscall.Timeval) float64 {
	return float64(tv.Sec) + float64(tv.Usec)/1e6
}
