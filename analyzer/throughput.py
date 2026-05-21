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

        tp = self.throughput_data[
            "throughput_mbps"
        ]

        # Remove idle windows
        tp = tp[tp > 0]

        if len(tp) < 10:
            return {
                "stability_score": None,
                "coefficient_of_variation": None,
                "stability_classification":
                    "Insufficient Data"
            }

        mean_tp = tp.mean()

        if mean_tp == 0:
            return {
                "stability_score": 0,
                "coefficient_of_variation": 100,
                "stability_classification":
                    "No Traffic"
            }

        cv = (
            tp.std()
            / mean_tp
        ) * 100

        # Relaxed thresholds for real networks
        if cv < 30:
            label = "Very Stable"
            score = 90

        elif cv < 60:
            label = "Stable"
            score = 75

        elif cv < 100:
            label = "Moderate"
            score = 55

        else:
            label = "Burst Traffic"
            score = 35

        return {
            "stability_score":
                round(score, 2),
            "coefficient_of_variation":
                round(cv, 2),
            "stability_classification":
                label
        }
    
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
