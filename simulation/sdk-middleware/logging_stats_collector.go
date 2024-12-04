package middleware

import (
	"fmt"
	"log"
	"os"
	"strings"
)

type LoggingStatsCollector struct {
	logger *log.Logger
}

func NewLoggingStatsCollector() *LoggingStatsCollector {
	logger := log.New(os.Stdout, "", 0) // Flags set to 0 to disable timestamps and prefixes
	return &LoggingStatsCollector{logger: logger}
}

func (c *LoggingStatsCollector) Collect(middlewareName string, methodName string, stats map[string]interface{}) {
	header := fmt.Sprintf("[STATS] %s for %s:", middlewareName, methodName)

	var statsLines []string
	for key, value := range stats {
		statsLines = append(statsLines, fmt.Sprintf("%s:%v", key, value))
	}
	statsContent := strings.Join(statsLines, "\n")
	logMessage := fmt.Sprintf("%s\n%s", header, statsContent)

	c.logger.Println(logMessage)
}
