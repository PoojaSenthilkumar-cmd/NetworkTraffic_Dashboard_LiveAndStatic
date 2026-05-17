"""
jitter.py
Jitter = RTT variation.
"""

import pandas as pd
import numpy as np
from analyzer.rtt import RTTAnalyzer


class JitterAnalyzer:

    def __init__(self, packets_df):
        self.df = packets_df
        self.jitter_data = None

    def analyze(self):

        rtt_results = (
            RTTAnalyzer(
                self.df
            ).analyze()
        )

        if not rtt_results:
            return {}

        rtt_df = rtt_results[
            "dataframe"
        ].copy()

        if len(rtt_df) < 2:
            return {}

        rtt_df = rtt_df.sort_values(
            "timestamp"
        )

        rtt_df[
            "jitter_ms"
        ] = (
            rtt_df[
                "rtt_ms"
            ]
            .diff()
            .abs()
        )

        rtt_df = rtt_df.dropna()

        self.jitter_data = pd.DataFrame({
            "timestamp":
                rtt_df[
                    "timestamp"
                ],
            "jitter_ms":
                rtt_df[
                    "jitter_ms"
                ]
        })

        return {
            "dataframe":
                self.jitter_data,
            "statistics":
                self._stats()
        }

    def _stats(self):

        j = self.jitter_data[
            "jitter_ms"
        ]

        return {
            "mean_jitter":
                j.mean(),
            "median_jitter":
                j.median(),
            "min_jitter":
                j.min(),
            "max_jitter":
                j.max(),
            "std_jitter":
                j.std(),
            "count":
                len(j)
        }