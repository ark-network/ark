#!/usr/bin/env bash

###############################################################################
# Usage:
#   ./create_dashboards.sh <grafana_api_key>
#
# Description:
#   This script creates four Grafana dashboards using the Grafana API:
#     1) Up/Down & Scrape Health
#     2) System Metrics
#     3) Process-Specific Metrics
#     4) RPC Metrics
#
#   The API key must be passed as the first argument.
#
# Example:
#   ./create_dashboards.sh eyJrIjoiOTkxZ...
###############################################################################

# Exit on any error
set -e

# Check for an API key
if [ -z "$1" ]; then
  echo "Usage: $0 <grafana_api_key>"
  exit 1
fi

API_KEY="$1"
GRAFANA_URL="http://localhost:3333"  # Grafana is on port 3333

###############################################################################
# 1. Basic “Up/Down” and Scrape Health
###############################################################################
DASHBOARD_HEALTH=$(cat <<EOF
{
  "dashboard": {
    "uid": "health-scrape",
    "title": "Up/Down & Scrape Health",
    "tags": ["health", "scrape"],
    "timezone": "browser",
    "schemaVersion": 27,
    "version": 0,
    "panels": [
      {
        "type": "row",
        "title": "Exporter Health",
        "gridPos": { "x": 0, "y": 0, "w": 24, "h": 1 }
      },
      {
        "type": "stat",
        "title": "Up (Exporter)",
        "description": "Shows if the exporter or target is up (1) or down (0).",
        "gridPos": { "x": 0, "y": 1, "w": 4, "h": 4 },
        "targets": [
          {
            "expr": "up"
          }
        ],
        "options": {
          "reduceOptions": { "calcs": ["lastNotNull"] },
          "orientation": "horizontal"
        }
      },
      {
        "type": "row",
        "title": "Scrape Health",
        "gridPos": { "x": 0, "y": 5, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "Scrape Duration Seconds",
        "description": "Duration of Prometheus scrape.",
        "gridPos": { "x": 0, "y": 6, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "scrape_duration_seconds",
            "legendFormat": "Scrape Duration"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "Scrape Samples Scraped",
        "description": "Number of samples scraped.",
        "gridPos": { "x": 12, "y": 6, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "scrape_samples_scraped",
            "legendFormat": "Samples Scraped"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "Scrape Samples Post Metric Relabeling",
        "gridPos": { "x": 0, "y": 13, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "scrape_samples_post_metric_relabeling",
            "legendFormat": "Samples (After Relabel)"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "Scrape Series Added",
        "gridPos": { "x": 12, "y": 13, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "scrape_series_added",
            "legendFormat": "Series Added"
          }
        ]
      }
    ]
  },
  "folderId": 0,
  "overwrite": true
}
EOF
)

echo "Creating Dashboard: Up/Down & Scrape Health..."
curl -s -X POST \
     -H "Authorization: Bearer $API_KEY" \
     -H "Content-Type: application/json" \
     -d "$DASHBOARD_HEALTH" \
     "$GRAFANA_URL/api/dashboards/db"
echo "Dashboard created: Up/Down & Scrape Health."

###############################################################################
# 2. System Metrics (Infrastructure)
###############################################################################
DASHBOARD_SYSTEM=$(cat <<EOF
{
  "dashboard": {
    "uid": "system-metrics",
    "title": "System Metrics",
    "tags": ["system", "infrastructure"],
    "timezone": "browser",
    "schemaVersion": 27,
    "version": 0,
    "panels": [
      {
        "type": "row",
        "title": "CPU",
        "gridPos": { "x": 0, "y": 0, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "CPU Load Averages",
        "description": "system_cpu_load_average_1m, 5m, 15m",
        "gridPos": { "x": 0, "y": 1, "w": 24, "h": 7 },
        "targets": [
          {
            "expr": "system_cpu_load_average_1m",
            "legendFormat": "Load 1m"
          },
          {
            "expr": "system_cpu_load_average_5m",
            "legendFormat": "Load 5m"
          },
          {
            "expr": "system_cpu_load_average_15m",
            "legendFormat": "Load 15m"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "CPU Time (per mode)",
        "description": "system_cpu_time_seconds_total",
        "gridPos": { "x": 0, "y": 8, "w": 24, "h": 7 },
        "targets": [
          {
            "expr": "increase(system_cpu_time_seconds_total[1m])",
            "legendFormat": "{{cpu}}-{{mode}}"
          }
        ]
      },
      {
        "type": "row",
        "title": "Memory",
        "gridPos": { "x": 0, "y": 15, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "Memory Usage",
        "description": "system_memory_usage_bytes",
        "gridPos": { "x": 0, "y": 16, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "system_memory_usage_bytes",
            "legendFormat": "Memory Usage Bytes"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "Paging Usage & Faults",
        "description": "system_paging_usage_bytes, system_paging_faults_total",
        "gridPos": { "x": 12, "y": 16, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "system_paging_usage_bytes",
            "legendFormat": "Paging Usage Bytes"
          },
          {
            "expr": "rate(system_paging_faults_total[1m])",
            "legendFormat": "Paging Faults/s"
          }
        ]
      },
      {
        "type": "row",
        "title": "Disk",
        "gridPos": { "x": 0, "y": 23, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "Disk IO (Bytes)",
        "gridPos": { "x": 0, "y": 24, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "rate(system_disk_io_bytes_total[1m])",
            "legendFormat": "Disk I/O Bytes/s"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "Disk IO Time & Operations",
        "gridPos": { "x": 12, "y": 24, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "rate(system_disk_io_time_seconds_total[1m])",
            "legendFormat": "Disk IO Time/s"
          },
          {
            "expr": "rate(system_disk_operations_total[1m])",
            "legendFormat": "Disk Ops/s"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "Filesystem Usage & Inodes",
        "description": "system_filesystem_usage_bytes, system_filesystem_inodes_usage",
        "gridPos": { "x": 0, "y": 31, "w": 24, "h": 7 },
        "targets": [
          {
            "expr": "system_filesystem_usage_bytes",
            "legendFormat": "Filesystem Usage Bytes"
          },
          {
            "expr": "system_filesystem_inodes_usage",
            "legendFormat": "Filesystem Inodes Usage"
          }
        ]
      },
      {
        "type": "row",
        "title": "Network",
        "gridPos": { "x": 0, "y": 38, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "Network Throughput (bytes)",
        "gridPos": { "x": 0, "y": 39, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "rate(system_network_io_bytes_total[1m])",
            "legendFormat": "Network Bytes/s"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "Network Packets & Errors",
        "gridPos": { "x": 12, "y": 39, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "rate(system_network_packets_total[1m])",
            "legendFormat": "Packets/s"
          },
          {
            "expr": "rate(system_network_errors_total[1m])",
            "legendFormat": "Errors/s"
          },
          {
            "expr": "rate(system_network_dropped_total[1m])",
            "legendFormat": "Dropped/s"
          }
        ]
      },
      {
        "type": "row",
        "title": "Processes",
        "gridPos": { "x": 0, "y": 46, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "Processes & Created",
        "description": "system_processes_count, system_processes_created_total",
        "gridPos": { "x": 0, "y": 47, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "system_processes_count",
            "legendFormat": "Processes Count"
          },
          {
            "expr": "rate(system_processes_created_total[1m])",
            "legendFormat": "Processes Created/s"
          }
        ]
      }
    ]
  },
  "folderId": 0,
  "overwrite": true
}
EOF
)

echo "Creating Dashboard: System Metrics..."
curl -s -X POST \
     -H "Authorization: Bearer $API_KEY" \
     -H "Content-Type: application/json" \
     -d "$DASHBOARD_SYSTEM" \
     "$GRAFANA_URL/api/dashboards/db"
echo "Dashboard created: System Metrics."

###############################################################################
# 3. Process-Specific Metrics
###############################################################################
DASHBOARD_PROCESS=$(cat <<EOF
{
  "dashboard": {
    "uid": "process-metrics",
    "title": "Process-Specific Metrics",
    "tags": ["process"],
    "timezone": "browser",
    "schemaVersion": 27,
    "version": 0,
    "panels": [
      {
        "type": "row",
        "title": "Process CPU",
        "gridPos": { "x": 0, "y": 0, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "Process CPU Time",
        "description": "process_cpu_time_seconds_total",
        "gridPos": { "x": 0, "y": 1, "w": 24, "h": 7 },
        "targets": [
          {
            "expr": "increase(process_cpu_time_seconds_total[1m])",
            "legendFormat": "Process CPU Time/s"
          }
        ]
      },
      {
        "type": "row",
        "title": "Process Disk",
        "gridPos": { "x": 0, "y": 8, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "Process Disk I/O",
        "description": "process_disk_io_bytes_total",
        "gridPos": { "x": 0, "y": 9, "w": 24, "h": 7 },
        "targets": [
          {
            "expr": "rate(process_disk_io_bytes_total[1m])",
            "legendFormat": "Disk I/O Bytes/s"
          }
        ]
      },
      {
        "type": "row",
        "title": "Process Memory",
        "gridPos": { "x": 0, "y": 16, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "Process Memory Usage",
        "description": "process_memory_usage_bytes, process_memory_virtual_bytes",
        "gridPos": { "x": 0, "y": 17, "w": 24, "h": 7 },
        "targets": [
          {
            "expr": "process_memory_usage_bytes",
            "legendFormat": "Physical Memory"
          },
          {
            "expr": "process_memory_virtual_bytes",
            "legendFormat": "Virtual Memory"
          }
        ]
      }
    ]
  },
  "folderId": 0,
  "overwrite": true
}
EOF
)

echo "Creating Dashboard: Process-Specific Metrics..."
curl -s -X POST \
     -H "Authorization: Bearer $API_KEY" \
     -H "Content-Type: application/json" \
     -d "$DASHBOARD_PROCESS" \
     "$GRAFANA_URL/api/dashboards/db"
echo "Dashboard created: Process-Specific Metrics."

###############################################################################
# 4. RPC Metrics
###############################################################################
# We'll build panels for the histogram-based metrics:
# - Duration: avg + p95
# - Request size: avg + p95
# - Requests per RPC: avg + p95
# - Response size: avg + p95
# - Responses per RPC: avg + p95
# We do 5 rows, each with 2 panels.

DASHBOARD_RPC=$(cat <<EOF
{
  "dashboard": {
    "uid": "rpc-metrics",
    "title": "RPC Metrics",
    "tags": ["rpc", "performance"],
    "timezone": "browser",
    "schemaVersion": 27,
    "version": 0,
    "panels": [
      {
        "type": "row",
        "title": "RPC Duration",
        "gridPos": { "x": 0, "y": 0, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "RPC Duration (Avg)",
        "description": "Average of rpc_server_duration_milliseconds histogram.",
        "gridPos": { "x": 0, "y": 1, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "rate(rpc_server_duration_milliseconds_sum[5m]) / rate(rpc_server_duration_milliseconds_count[5m])",
            "legendFormat": "Avg Duration (ms)"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "RPC Duration (p95)",
        "description": "95th percentile of rpc_server_duration_milliseconds.",
        "gridPos": { "x": 12, "y": 1, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(rpc_server_duration_milliseconds_bucket[5m]))",
            "legendFormat": "p95 Duration (ms)"
          }
        ]
      },
      {
        "type": "row",
        "title": "RPC Request Size",
        "gridPos": { "x": 0, "y": 8, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "Request Size (Avg)",
        "gridPos": { "x": 0, "y": 9, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "rate(rpc_server_request_size_bytes_sum[5m]) / rate(rpc_server_request_size_bytes_count[5m])",
            "legendFormat": "Avg Request Size (bytes)"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "Request Size (p95)",
        "gridPos": { "x": 12, "y": 9, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(rpc_server_request_size_bytes_bucket[5m]))",
            "legendFormat": "p95 Request Size (bytes)"
          }
        ]
      },
      {
        "type": "row",
        "title": "RPC Requests per RPC",
        "gridPos": { "x": 0, "y": 16, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "Requests per RPC (Avg)",
        "gridPos": { "x": 0, "y": 17, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "rate(rpc_server_requests_per_rpc_sum[5m]) / rate(rpc_server_requests_per_rpc_count[5m])",
            "legendFormat": "Avg Requests/RPC"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "Requests per RPC (p95)",
        "gridPos": { "x": 12, "y": 17, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(rpc_server_requests_per_rpc_bucket[5m]))",
            "legendFormat": "p95 Requests/RPC"
          }
        ]
      },
      {
        "type": "row",
        "title": "RPC Response Size",
        "gridPos": { "x": 0, "y": 24, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "Response Size (Avg)",
        "gridPos": { "x": 0, "y": 25, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "rate(rpc_server_response_size_bytes_sum[5m]) / rate(rpc_server_response_size_bytes_count[5m])",
            "legendFormat": "Avg Response Size (bytes)"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "Response Size (p95)",
        "gridPos": { "x": 12, "y": 25, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(rpc_server_response_size_bytes_bucket[5m]))",
            "legendFormat": "p95 Response Size (bytes)"
          }
        ]
      },
      {
        "type": "row",
        "title": "RPC Responses per RPC",
        "gridPos": { "x": 0, "y": 32, "w": 24, "h": 1 }
      },
      {
        "type": "timeseries",
        "title": "Responses per RPC (Avg)",
        "gridPos": { "x": 0, "y": 33, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "rate(rpc_server_responses_per_rpc_sum[5m]) / rate(rpc_server_responses_per_rpc_count[5m])",
            "legendFormat": "Avg Responses/RPC"
          }
        ]
      },
      {
        "type": "timeseries",
        "title": "Responses per RPC (p95)",
        "gridPos": { "x": 12, "y": 33, "w": 12, "h": 7 },
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(rpc_server_responses_per_rpc_bucket[5m]))",
            "legendFormat": "p95 Responses/RPC"
          }
        ]
      }
    ]
  },
  "folderId": 0,
  "overwrite": true
}
EOF
)

echo "Creating Dashboard: RPC Metrics..."
curl -s -X POST \
     -H "Authorization: Bearer $API_KEY" \
     -H "Content-Type: application/json" \
     -d "$DASHBOARD_RPC" \
     "$GRAFANA_URL/api/dashboards/db"
echo "Dashboard created: RPC Metrics."

###############################################################################
# Done!
###############################################################################
echo "All dashboards have been created successfully!"
