package middleware

type CompositeStatsCollector struct {
	collectors []StatsCollector
}

func NewCompositeStatsCollector(collectors ...StatsCollector) *CompositeStatsCollector {
	return &CompositeStatsCollector{collectors: collectors}
}

func (c *CompositeStatsCollector) Collect(middlewareName string, methodName string, stats map[string]interface{}) {
	for _, collector := range c.collectors {
		collector.Collect(middlewareName, methodName, stats)
	}
}
