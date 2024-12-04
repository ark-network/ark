package middleware

type StatsCollector interface {
	Collect(middlewareName string, methodName string, stats map[string]interface{})
}
