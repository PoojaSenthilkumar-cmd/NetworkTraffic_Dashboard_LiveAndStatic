"""
tcp_analysis.py
TCP behavior analysis:
1. Slow Start Duration
2. Retransmission Bursts
3. Half-Open Connections
"""

import pandas as pd
from collections import defaultdict


class TCPAnalyzer:

    def __init__(self, packets_df):

        self.df = packets_df.copy()

        self.tcp_packets = self.df[
            self.df["protocol"] == "TCP"
        ].copy()

    # =====================================================
    # SLOW START
    # =====================================================

    def analyze_tcp_slow_start(self):

        if self.tcp_packets.empty:
            return {}

        tcp = self.tcp_packets.sort_values(
            "timestamp"
        )

        slow_start_events = []

        flows = tcp.groupby([
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port"
        ])

        for flow, packets in flows:

            packets = packets.reset_index(
                drop=True
            )

            syn_index = None

            # Find SYN
            for idx, pkt in packets.iterrows():

                flags = str(
                    pkt["flags"]
                )

                if (
                    "S" in flags
                    and "A" not in flags
                ):
                    syn_index = idx
                    break

            if syn_index is None:
                continue

            syn_packet = packets.iloc[
                syn_index
            ]

            start_time = syn_packet[
                "timestamp"
            ]

            packet_sizes = []

            # examine first packets
            for i in range(
                syn_index,
                min(
                    syn_index + 15,
                    len(packets)
                )
            ):

                pkt = packets.iloc[i]

                if pkt["size"] > 64:
                    packet_sizes.append(
                        pkt["size"]
                    )

            if len(packet_sizes) < 2:
                continue

            end_time = packets.iloc[
                min(
                    syn_index + 10,
                    len(packets) - 1
                )
            ]["timestamp"]

            duration = (
                end_time
                - start_time
            ).total_seconds() * 1000

            if 0 < duration < 10000:

                slow_start_events.append({
                    "timestamp":
                        start_time,
                    "flow":
                        (
                            f"{flow[0]}"
                            f":{flow[2]}"
                            f" -> "
                            f"{flow[1]}"
                            f":{flow[3]}"
                        ),
                    "slow_start_duration_ms":
                        duration,
                    "src_ip":
                        flow[0],
                    "dst_ip":
                        flow[1],
                    "initial_window_packets":
                        len(
                            packet_sizes
                        )
                })

        df = pd.DataFrame(
            slow_start_events
        )

        if df.empty:
            return {}

        return {
            "dataframe": df,
            "statistics": {
                "total_events":
                    len(df),
                "mean_duration":
                    df[
                        "slow_start_duration_ms"
                    ].mean(),
                "median_duration":
                    df[
                        "slow_start_duration_ms"
                    ].median()
            }
        }

    # =====================================================
    # RETRANSMISSION BURSTS
    # =====================================================

    def analyze_retransmission_bursts(self):

        if self.tcp_packets.empty:
            return {}

        retrans_events = []

        flows = self.tcp_packets.groupby([
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port"
        ])

        for flow, packets in flows:

            packets = packets.sort_values(
                "timestamp"
            )

            ack_counter = defaultdict(
                list
            )

            for _, pkt in (
                packets.iterrows()
            ):

                ack = pkt[
                    "ack_num"
                ]

                if pd.notna(ack):
                    ack_counter[
                        ack
                    ].append(
                        pkt[
                            "timestamp"
                        ]
                    )

            for (
                ack,
                times
            ) in ack_counter.items():

                if len(times) >= 3:

                    burst_time = (
                        times[-1]
                        - times[0]
                    ).total_seconds()

                    if burst_time <= 1:

                        count = len(
                            times
                        )

                        retrans_events.append({
                            "timestamp":
                                times[0],
                            "flow":
                                (
                                    f"{flow[0]}"
                                    f":{flow[2]}"
                                    f" -> "
                                    f"{flow[1]}"
                                    f":{flow[3]}"
                                ),
                            "ack_number":
                                ack,
                            "duplicate_count":
                                count,
                            "severity":
                                (
                                    "High"
                                    if count >= 5
                                    else "Medium"
                                )
                        })

        df = pd.DataFrame(
            retrans_events
        )

        if df.empty:
            return {}

        return {
            "dataframe":
                df,
            "statistics": {
                "total_bursts":
                    len(df),
                "mean_duplicates_per_burst":
                    df[
                        "duplicate_count"
                    ].mean(),
                "high_severity_bursts":
                    len(
                        df[
                            df[
                                "severity"
                            ]
                            == "High"
                        ]
                    )
            }
        }

    # =====================================================
    # HALF OPEN CONNECTIONS
    # =====================================================

    def analyze_half_open_connections(self):

        if self.tcp_packets.empty:
            return {}

        packets = (
            self.tcp_packets
            .sort_values(
                "timestamp"
            )
            .reset_index(
                drop=True
            )
        )

        half_open = []

        for idx, pkt in (
            packets.iterrows()
        ):

            flags = str(
                pkt["flags"]
            )

            # SYN only
            if (
                "S" in flags
                and "A" not in flags
            ):

                src_ip = pkt[
                    "src_ip"
                ]
                dst_ip = pkt[
                    "dst_ip"
                ]
                src_port = pkt[
                    "src_port"
                ]
                dst_port = pkt[
                    "dst_port"
                ]

                timestamp = pkt[
                    "timestamp"
                ]

                future = packets[
                    packets[
                        "timestamp"
                    ]
                    > timestamp
                ].head(50)

                synack = future[
                    (
                        future[
                            "src_ip"
                        ]
                        == dst_ip
                    )
                    &
                    (
                        future[
                            "dst_ip"
                        ]
                        == src_ip
                    )
                ]

                synack_found = False
                ack_found = False

                for _, p in (
                    synack.iterrows()
                ):

                    flg = str(
                        p["flags"]
                    )

                    if (
                        "S" in flg
                        and "A" in flg
                    ):
                        synack_found = True

                    if (
                        flg == "A"
                    ):
                        ack_found = True

                if (
                    synack_found
                    and not ack_found
                ):

                    half_open.append({
                        "timestamp":
                            timestamp,
                        "flow":
                            (
                                f"{src_ip}"
                                f":{src_port}"
                                f" -> "
                                f"{dst_ip}"
                                f":{dst_port}"
                            ),
                        "src_ip":
                            src_ip,
                        "dst_ip":
                            dst_ip,
                        "src_port":
                            src_port,
                        "dst_port":
                            dst_port,
                        "issue":
                            "Missing ACK"
                    })

        df = pd.DataFrame(
            half_open
        )

        if df.empty:
            return {}

        return {
            "dataframe":
                df,
            "statistics": {
                "total_half_open":
                    len(df),
                "unique_flows":
                    df[
                        "flow"
                    ].nunique()
            }
        }

    # =====================================================
    # RUN ALL
    # =====================================================

    def get_all_tcp_analysis(self):

        return {
            "slow_start":
                self.analyze_tcp_slow_start(),

            "retransmission":
                self.analyze_retransmission_bursts(),

            "half_open":
                self.analyze_half_open_connections()
        }