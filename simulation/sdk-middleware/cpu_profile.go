package middleware

import (
	"context"
	"fmt"
	"os"
	"runtime/pprof"
	"time"
)

type CPUProfileMiddleware struct {
	statsCollector StatsCollector
	profileDir     string
}

func NewCPUProfileMiddleware(statsCollector StatsCollector, profileDir string) *CPUProfileMiddleware {
	return &CPUProfileMiddleware{
		statsCollector: statsCollector,
		profileDir:     profileDir,
	}
}

const cpuProfileFileKey = contextKey("cpuProfileFile")

func (m *CPUProfileMiddleware) Before(ctx context.Context, methodName string, args []interface{}) context.Context {
	profilePath := fmt.Sprintf("%s/cpu_%s_%d.prof", m.profileDir, methodName, time.Now().UnixNano())
	f, err := os.Create(profilePath)
	if err != nil {
		return ctx
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		f.Close()
		return ctx
	}
	return context.WithValue(ctx, cpuProfileFileKey, f)
}

func (m *CPUProfileMiddleware) After(ctx context.Context, methodName string, results []interface{}, err error) {
	f, ok := ctx.Value(cpuProfileFileKey).(*os.File)
	if !ok {
		return
	}
	pprof.StopCPUProfile()
	f.Close()
	stats := map[string]interface{}{
		"profile_path": f.Name(),
	}
	m.statsCollector.Collect("CPUProfileMiddleware", methodName, stats)
}
