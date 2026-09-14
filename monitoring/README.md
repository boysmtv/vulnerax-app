# Monitoring Stack — D:\Work\Pribadi\WebProject\vulnerax-app\monitoring

## Components

- **Prometheus** (port 9090) — Metrics storage and alerting
- **OpenTelemetry Collector** (ports 4317/4318) — Trace and metric ingestion
- **Grafana** (port 3000) — Dashboard and visualization
- **Alerting Rules** — Pre-configured alerts for error rate, latency, and uptime

## Quick Start

```bash
docker compose -f monitoring/docker-compose.yml up -d
```

## Integration

1. Instrument your app with OpenTelemetry SDK pointing to `localhost:4317`
2. Prometheus scrapes metrics from OTEL collector at `localhost:8889`
3. Grafana dashboards auto-provisioned at port 3000
