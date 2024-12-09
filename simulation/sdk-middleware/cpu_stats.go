package middleware

import (
	"context"
	"syscall"
	"time"
)

type CPUUtilizationMiddleware struct {
	statsCollector StatsCollector
}

func NewCPUUtilizationMiddleware(statsCollector StatsCollector) *CPUUtilizationMiddleware {
	return &CPUUtilizationMiddleware{statsCollector: statsCollector}
}

const cpuUtilizationDataKey = contextKey("cpuUtilizationData")

type cpuUtilizationData struct {
	startRusage syscall.Rusage
	startTime   time.Time
}

func (m *CPUUtilizationMiddleware) Before(ctx context.Context, methodName string, args []interface{}) context.Context {
	var startRusage syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &startRusage)
	startTime := time.Now()
	data := &cpuUtilizationData{
		startRusage: startRusage,
		startTime:   startTime,
	}
	return context.WithValue(ctx, cpuUtilizationDataKey, data)
}

func (m *CPUUtilizationMiddleware) After(ctx context.Context, methodName string, results []interface{}, err error) {
	data, ok := ctx.Value(cpuUtilizationDataKey).(*cpuUtilizationData)
	if !ok {
		return
	}
	var endRusage syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &endRusage)
	duration := time.Since(data.startTime)
	userTimeDiff := timeval2float64(endRusage.Utime) - timeval2float64(data.startRusage.Utime)
	sysTimeDiff := timeval2float64(endRusage.Stime) - timeval2float64(data.startRusage.Stime)
	totalCPUTime := userTimeDiff + sysTimeDiff
	cpuPercentage := (totalCPUTime / duration.Seconds()) * 100

	stats := map[string]interface{}{
		"duration_seconds":    duration.Seconds(),
		"cpu_percentage":      cpuPercentage,
		"user_time_seconds":   userTimeDiff,
		"system_time_seconds": sysTimeDiff,
		"total_cpu_time":      totalCPUTime,
	}
	m.statsCollector.Collect("CPUUtilizationMiddleware", methodName, stats)
}

func timeval2float64(tv syscall.Timeval) float64 {
	return float64(tv.Sec) + float64(tv.Usec)/1e6
}
