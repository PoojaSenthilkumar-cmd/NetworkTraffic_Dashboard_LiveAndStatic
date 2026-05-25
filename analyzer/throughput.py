"""
throughput.py
Throughput stability analysis.
"""

import pandas as pd
from datetime import timedelta


ACCEPTABLE_THRESHOLD_MBPS = 25.0


class ThroughputAnalyzer:

    def __init__(self, packets_df):
        self.df = packets_df.copy()
        self.throughput_data = None

    def analyze(self, time_window_ms=5000):

        if self.df.empty:
            return {}

        packets = self.df.sort_values("timestamp")
        start_time = packets["timestamp"].min()
        end_time = packets["timestamp"].max()
        delta = timedelta(milliseconds=time_window_ms)
        throughput_results = []
        current_time = start_time

        while current_time < end_time:
            window_end = current_time + delta
            window_packets = packets[
                (packets["timestamp"] >= current_time) &
                (packets["timestamp"] < window_end)
            ]
            total_bytes = window_packets["size"].sum()
            duration_sec = time_window_ms / 1000
            throughput_mbps = (total_bytes * 8) / (duration_sec * 1000000)
            throughput_results.append({
                "timestamp": current_time,
                "throughput_mbps": throughput_mbps,
                "bytes_transferred": total_bytes,
                "packet_count": len(window_packets)
            })
            current_time = window_end

        self.throughput_data = pd.DataFrame(throughput_results)

        return {
            "dataframe": self.throughput_data,
            "statistics": self._statistics(),
            "stability_metric": self._stability()
        }

    def _statistics(self):

        all_tp = self.throughput_data["throughput_mbps"]
        active_tp = self.throughput_data[
            self.throughput_data["packet_count"] > 0
        ]["throughput_mbps"]

        return {
            "mean_throughput_mbps": all_tp.mean(),
            "median_throughput_mbps": all_tp.median(),
            "max_throughput_mbps": all_tp.max(),
            "min_throughput_mbps": all_tp.min(),
            "std_dev": all_tp.std(),
            "total_windows": len(all_tp),
            "active_windows": len(active_tp),
            "idle_windows": len(all_tp) - len(active_tp),
            "idle_ratio": round((len(all_tp) - len(active_tp)) / len(all_tp) * 100, 2)
        }

    def _stability(self):

        tp = self.throughput_data["throughput_mbps"]
        active_windows = tp[tp > 0]

        if self.throughput_data.empty:
            return {
                "stability_score": None,
                "stability_classification": "Insufficient Data",
                "anomalies_detected": 0,
                "is_burst_event": False,
                "burst_events": [],
                "acceptable_threshold_mbps": ACCEPTABLE_THRESHOLD_MBPS
            }

        if active_windows.empty:
            return {
                "stability_score": 100,
                "stability_classification": "Stable",
                "mean_throughput_mbps": 0,
                "std_dev_mbps": 0,
                "anomalies_detected": 0,
                "is_burst_event": False,
                "burst_events": [],
                "acceptable_threshold_mbps": ACCEPTABLE_THRESHOLD_MBPS,
                "recommendation": "Stable throughput within acceptable range"
            }

        mean_tp = active_windows.mean()
        std_tp = active_windows.std()
        anomalies = self._detect_abnormal_bursts(self.throughput_data)
        burst_count = len(anomalies)

        if burst_count == 0:
            classification = "Stable"
            score = 100
        elif burst_count <= 3:
            classification = "Moderate Variability"
            score = 60
        else:
            classification = "High Variability"
            score = 25

        has_anomalies = burst_count > 0

        return {
            "stability_score": round(score, 2),
            "stability_classification": classification,
            "mean_throughput_mbps": round(mean_tp, 2),
            "std_dev_mbps": round(std_tp, 2),
            "anomalies_detected": burst_count,
            "is_burst_event": has_anomalies,
            "burst_events": anomalies,
            "acceptable_threshold_mbps": ACCEPTABLE_THRESHOLD_MBPS,
            "recommendation": self._get_threshold_recommendation(
                classification,
                burst_count
            )
        }

    def _detect_abnormal_bursts(self, df):
        anomalies = []

        for index, row in df.iterrows():
            current = row["throughput_mbps"]

            if current > ACCEPTABLE_THRESHOLD_MBPS:
                anomalies.append({
                    "index": int(index),
                    "timestamp": row["timestamp"],
                    "current_mbps": round(current, 2),
                    "threshold_mbps": ACCEPTABLE_THRESHOLD_MBPS,
                    "excess_mbps": round(current - ACCEPTABLE_THRESHOLD_MBPS, 2),
                    "severity": "High",
                    "type": "Threshold Exceeded"
                })

        return anomalies

    def _get_threshold_recommendation(self, classification, burst_count):
        if classification == "High Variability":
            return (
                f"{burst_count} throughput sample(s) exceeded "
                f"{ACCEPTABLE_THRESHOLD_MBPS:.1f} Mbps - investigate congestion"
            )
        if classification == "Moderate Variability":
            return (
                f"{burst_count} throughput sample(s) exceeded "
                f"{ACCEPTABLE_THRESHOLD_MBPS:.1f} Mbps - monitor network conditions"
            )
        return "Stable throughput within acceptable range"
