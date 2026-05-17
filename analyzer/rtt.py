"""
rtt.py
Accurate TCP RTT analysis.
"""

import pandas as pd
import logging

logger = logging.getLogger(__name__)


class RTTAnalyzer:

    def __init__(self, packets_df):
        self.df = packets_df.copy()
        self.rtt_data = None

    def analyze(self):

        tcp = self.df[
            self.df["protocol"] == "TCP"
        ].copy()

        if tcp.empty:
            return {}

        tcp = tcp.sort_values("timestamp")

        rtt_results = []

        # Store sent packets waiting for ACK
        outstanding_packets = {}

        for _, pkt in tcp.iterrows():

            try:
                flow_key = (
                    pkt["src_ip"],
                    pkt["dst_ip"],
                    pkt["src_port"],
                    pkt["dst_port"]
                )

                reverse_flow = (
                    pkt["dst_ip"],
                    pkt["src_ip"],
                    pkt["dst_port"],
                    pkt["src_port"]
                )

                seq = pkt["seq_num"]
                ack = pkt["ack_num"]
                payload_size = pkt.get(
                    "payload_size",
                    0
                )

                timestamp = pkt["timestamp"]

                # --------------------------
                # Track outgoing packets
                # --------------------------
                if pd.notna(seq):

                    expected_ack = (
                        seq + max(payload_size, 1)
                    )

                    outstanding_packets[
                        (
                            flow_key,
                            expected_ack
                        )
                    ] = {
                        "timestamp": timestamp,
                        "src_ip": pkt["src_ip"],
                        "dst_ip": pkt["dst_ip"],
                        "size": pkt["size"]
                    }

                # --------------------------
                # Match ACK packet
                # --------------------------
                if pd.notna(ack):

                    key = (
                        reverse_flow,
                        ack
                    )

                    if key in outstanding_packets:

                        original = outstanding_packets[key]

                        rtt = (
                            timestamp
                            - original["timestamp"]
                        ).total_seconds() * 1000

                        # sanity check
                        if 0 < rtt < 5000:

                            rtt_results.append({
                                "timestamp":
                                    timestamp,
                                "rtt_ms":
                                    rtt,
                                "src_ip":
                                    original[
                                        "src_ip"
                                    ],
                                "dst_ip":
                                    original[
                                        "dst_ip"
                                    ],
                                "packet_size":
                                    original[
                                        "size"
                                    ]
                            })

                            del outstanding_packets[key]

            except Exception:
                continue

        self.rtt_data = pd.DataFrame(
            rtt_results
        )

        if self.rtt_data.empty:
            return {}

        return {
            "dataframe":
                self.rtt_data,
            "statistics":
                self._stats(),
            "color_zones":
                self._zones()
        }

    def _stats(self):

        rtt = self.rtt_data[
            "rtt_ms"
        ]

        return {
            "mean_rtt": rtt.mean(),
            "median_rtt": rtt.median(),
            "min_rtt": rtt.min(),
            "max_rtt": rtt.max(),
            "std_rtt": rtt.std(),
            "count": len(rtt)
        }

    def _zones(self):

        return {
            "green":
                (0, 50),
            "orange":
                (50, 100),
            "red":
                (100, 999999)
        }