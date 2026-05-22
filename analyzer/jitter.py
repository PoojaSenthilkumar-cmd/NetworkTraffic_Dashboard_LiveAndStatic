"""
jitter.py
Jitter = variance in packet inter-arrival times.
"""

import pandas as pd
import numpy as np


class JitterAnalyzer:

    def __init__(self, packets_df):
        self.df = packets_df.copy()
        self.jitter_data = None

    def analyze(self):
        tcp = self.df[self.df["protocol"] == "TCP"].copy()

        if tcp.empty:
            return {}

        flows = tcp.groupby([
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port"
        ])

        jitter_results = []

        for flow_tuple, flow_packets in flows:
            src_ip, dst_ip, src_port, dst_port = flow_tuple
            flow_packets = flow_packets.sort_values("timestamp").reset_index(drop=True)

            if len(flow_packets) < 2:
                continue

            inter_arrival_times = []
            for i in range(1, len(flow_packets)):
                delta = (
                    flow_packets.iloc[i]["timestamp"] -
                    flow_packets.iloc[i - 1]["timestamp"]
                ).total_seconds() * 1000
                inter_arrival_times.append(delta)

            if len(inter_arrival_times) < 2:
                continue

            inter_arrivals = np.array(inter_arrival_times)
            mean_inter_arrival = np.mean(inter_arrivals)
            jitter = 0
            for delta in inter_arrivals:
                diff = abs(delta - mean_inter_arrival)
                jitter = jitter * 15/16 + diff / 16

            jitter_std = np.std(inter_arrivals) if len(inter_arrivals) > 1 else 0

            jitter_results.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "flow": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                "packet_count": len(flow_packets),
                "jitter_ms_rfc3550": jitter,
                "jitter_ms_std": jitter_std,
                "mean_inter_arrival_ms": mean_inter_arrival,
                "min_inter_arrival_ms": np.min(inter_arrivals),
                "max_inter_arrival_ms": np.max(inter_arrivals)
            })

        self.jitter_data = pd.DataFrame(jitter_results)

        if self.jitter_data.empty:
            return {}

        return {
            "dataframe": self.jitter_data,
            "statistics": self._stats()
        }

    def _stats(self):
        return {
            "mean_jitter_ms": self.jitter_data["jitter_ms_rfc3550"].mean(),
            "median_jitter_ms": self.jitter_data["jitter_ms_rfc3550"].median(),
            "max_jitter_ms": self.jitter_data["jitter_ms_rfc3550"].max(),
            "min_jitter_ms": self.jitter_data["jitter_ms_rfc3550"].min(),
            "total_flows": len(self.jitter_data)
        }
