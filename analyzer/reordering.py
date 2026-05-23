"""
reordering.py
Packet reordering detection.
"""

import pandas as pd


class ReorderingAnalyzer:

    def __init__(self, packets_df):
        self.df = packets_df
        self.reordering_data = None

    def analyze(self):

        tcp = self.df[
            self.df["protocol"]
            == "TCP"
        ].copy()

        if tcp.empty:
            return {}

        tcp = tcp.sort_values(
            "timestamp"
        )

        reorder_events = []

        total_packets = 0

        flows = tcp.groupby([
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port"
        ])

        for flow, group in flows:

            group = group.sort_values(
                "timestamp"
            )

            highest_seq = -1

            for _, pkt in (
                group.iterrows()
            ):

                seq = pkt[
                    "seq_num"
                ]

                if pd.isna(seq):
                    continue

                total_packets += 1

                # Out-of-order packet
                if seq < highest_seq:

                    reorder_events.append({
                        "timestamp":
                            pkt[
                                "timestamp"
                            ],
                        "flow":
                            f"{flow[0]}"
                            f":{flow[2]}"
                            f" -> "
                            f"{flow[1]}"
                            f":{flow[3]}",
                        "received_seq":
                            seq,
                        "expected_seq":
                            highest_seq
                    })

                highest_seq = max(
                    highest_seq,
                    seq
                )

        self.reordering_data = (
            pd.DataFrame(
                reorder_events
            )
        )

        percentage = 0

        if total_packets > 0:
            percentage = (
                len(
                    reorder_events
                )
                /
                total_packets
            ) * 100

        return {
            "dataframe":
                self.reordering_data,
            "statistics": {
                "total_reordering_events":
                    len(
                        reorder_events
                    ),
                "reordering_percentage":
                    percentage,
                "reordering_frequency":
                    len(
                        reorder_events
                    )
            }
        }