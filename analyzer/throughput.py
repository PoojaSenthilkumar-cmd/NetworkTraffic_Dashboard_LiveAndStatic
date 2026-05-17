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

    def analyze(self, time_window_ms=1000):

        if self.df.empty:
            return {}

        packets = self.df.sort_values(
            "timestamp"
        )

        start_time = packets[
            "timestamp"
        ].min()

        end_time = packets[
            "timestamp"
        ].max()

        delta = timedelta(
            milliseconds=time_window_ms
        )

        throughput_results = []

        current_time = start_time

        while current_time < end_time:

            window_end = (
                current_time + delta
            )

            window_packets = packets[
                (
                    packets[
                        "timestamp"
                    ] >= current_time
                )
                &
                (
                    packets[
                        "timestamp"
                    ] < window_end
                )
            ]

            total_bytes = (
                window_packets[
                    "size"
                ].sum()
            )

            duration_sec = (
                time_window_ms / 1000
            )

            # Correct Mbps formula
            throughput_mbps = (
                total_bytes
                * 8
            ) / (
                duration_sec
                * 1_000_000
            )

            throughput_results.append({
                "timestamp":
                    current_time,
                "throughput_mbps":
                    throughput_mbps,
                "bytes_transferred":
                    total_bytes,
                "packet_count":
                    len(window_packets)
            })

            current_time = (
                window_end
            )

        self.throughput_data = (
            pd.DataFrame(
                throughput_results
            )
        )

        return {
            "dataframe":
                self.throughput_data,
            "statistics":
                self._statistics(),
            "stability_metric":
                self._stability()
        }

    def _statistics(self):

        tp = self.throughput_data[
            "throughput_mbps"
        ]

        return {
            "mean_throughput_mbps":
                tp.mean(),
            "median_throughput_mbps":
                tp.median(),
            "max_throughput_mbps":
                tp.max(),
            "min_throughput_mbps":
                tp.min(),
            "std_dev":
                tp.std(),
            "total_windows":
                len(tp)
        }

    def _stability(self):

        tp = self.throughput_data[
            "throughput_mbps"
        ]

        mean_tp = tp.mean()

        if mean_tp == 0:
            score = 0
            cv = 100
        else:
            cv = (
                tp.std()
                / mean_tp
            ) * 100

            score = max(
                0,
                100 - cv
            )

        if score >= 80:
            label = "Very Stable"
        elif score >= 60:
            label = "Stable"
        elif score >= 40:
            label = "Moderate"
        else:
            label = "Unstable"

        return {
            "stability_score":
                round(score, 2),
            "coefficient_of_variation":
                round(cv, 2),
            "stability_classification":
                label
        }