"""
throughput.py
Throughput stability analysis.
"""

import pandas as pd
from datetime import timedelta


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

        if len(active_windows) < 10:
            return {
                "stability_score": None,
                "coefficient_of_variation": None,
                "stability_classification": "Insufficient Data",
                "anomalies_detected": 0,
                "is_burst_event": False,
                "burst_events": []
            }

        mean_tp = active_windows.mean()
        std_tp = active_windows.std()

        if mean_tp == 0:
            return {
                "stability_score": 0,
                "coefficient_of_variation": 0,
                "stability_classification": "No Traffic",
                "anomalies_detected": 0,
                "is_burst_event": False,
                "burst_events": [],
                "recommendation": "No traffic detected"
            }

        cv = (std_tp / mean_tp) * 100
        anomalies = self._detect_abnormal_bursts(
            self.throughput_data,
            mean_tp,
            std_tp
        )

        if cv < 20:
            classification = "Excellent Stability"
            score = 95
        elif cv < 35:
            classification = "Very Stable"
            score = 85
        elif cv < 60:
            classification = "Stable"
            score = 70
        elif cv < 100:
            classification = "Moderate"
            score = 50
        else:
            classification = "High Variability"
            score = 25

        has_anomalies = len(anomalies) > 0

        return {
            "stability_score": round(score, 2),
            "coefficient_of_variation": round(cv, 2),
            "stability_classification": classification,
            "mean_throughput_mbps": round(mean_tp, 2),
            "std_dev_mbps": round(std_tp, 2),
            "anomalies_detected": len(anomalies),
            "is_burst_event": has_anomalies,
            "burst_events": anomalies,
            "recommendation": self._get_recommendation(cv, has_anomalies)
        }

    def _detect_abnormal_bursts(self, df, mean_tp, std_tp):
        tp = df[df["throughput_mbps"] > 0]["throughput_mbps"].reset_index(drop=True)

        if len(tp) < 5:
            return []

        anomalies = []

        for i in range(1, len(tp)):
            current = tp.iloc[i]
            previous = tp.iloc[i - 1]
            change_pct = abs(current - previous) / (previous + 1e-6) * 100

            if change_pct > 50:
                severity = "High" if change_pct > 80 else "Medium"
                anomalies.append({
                    "index": i,
                    "previous_mbps": round(previous, 2),
                    "current_mbps": round(current, 2),
                    "change_percent": round(change_pct, 2),
                    "severity": severity,
                    "type": "Drop" if current < previous else "Spike"
                })
            elif std_tp > 0 and abs(current - mean_tp) > 2 * std_tp:
                anomalies.append({
                    "index": i,
                    "value_mbps": round(current, 2),
                    "mean_mbps": round(mean_tp, 2),
                    "std_devs_away": round(abs(current - mean_tp) / std_tp, 2),
                    "severity": "Low",
                    "type": "Outlier"
                })

        return anomalies

    def _get_recommendation(self, cv, has_anomalies):
        if has_anomalies:
            return "⚠️ Abnormal burst detected - investigate congestion"
        elif cv > 60:
            return "⚠️ High variability - monitor network conditions"
        elif cv > 35:
            return "✓ Normal TCP behavior - acceptable"
        else:
            return "✓ Excellent fiber performance"
    
    # def _stability(self):

    #     active_windows = self.throughput_data[
    #         self.throughput_data["packet_count"] > 0
    #     ]

    #     if active_windows.empty:
    #         return {
    #             "stability_score": 0.0,
    #             "coefficient_of_variation": 0.0,
    #             "stability_classification": "No Active Traffic"
    #         }

    #     tp = active_windows["throughput_mbps"]
    #     mean_tp = tp.mean()
    #     std_tp = tp.std()

    #     if mean_tp == 0 or pd.isna(mean_tp):
    #         score = 0.0
    #         cv = 0.0
    #     else:
    #         cv = (std_tp / mean_tp) * 100
    #         score = max(0.0, 100.0 - cv)

    #     if score >= 80:
    #         label = "Very Stable"
    #     elif score >= 60:
    #         label = "Stable"
    #     elif score >= 40:
    #         label = "Moderate"
    #     else:
    #         label = "Unstable"

    #     return {
    #         "stability_score": round(score, 2),
    #         "coefficient_of_variation": round(cv, 2),
    #         "stability_classification": label
    #     }
