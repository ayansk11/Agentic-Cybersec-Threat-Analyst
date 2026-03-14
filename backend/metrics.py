"""Prometheus custom metrics for threat analysis."""

from prometheus_client import Counter, Histogram

analysis_total = Counter(
    "threat_analysis_total",
    "Total number of threat analyses completed",
    ["severity"],
)

analysis_duration = Histogram(
    "threat_analysis_duration_seconds",
    "Duration of threat analysis pipeline",
    buckets=[1, 5, 10, 30, 60, 120, 300],
)

agent_errors = Counter(
    "agent_errors_total",
    "Total agent pipeline errors",
    ["agent_name"],
)
