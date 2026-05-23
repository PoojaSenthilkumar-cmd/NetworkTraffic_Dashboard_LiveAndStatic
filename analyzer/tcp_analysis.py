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
            ).reset_index(drop=True)

            ack_sequence = []

            for _, pkt in packets.iterrows():
                ack = pkt["ack_num"]
                timestamp = pkt["timestamp"]

                if pd.notna(ack):
                    ack_sequence.append({
                        "ack": ack,
                        "timestamp": timestamp
                    })

            if len(ack_sequence) < 3:
                continue

            i = 0
            while i < len(ack_sequence) - 2:
                if (
                    ack_sequence[i]["ack"] == ack_sequence[i + 1]["ack"] ==
                    ack_sequence[i + 2]["ack"]
                ):
                    ack_num = ack_sequence[i]["ack"]
                    start_time = ack_sequence[i]["timestamp"]
                    dup_count = 3
                    j = i + 3

                    while j < len(ack_sequence) and ack_sequence[j]["ack"] == ack_num:
                        if (
                            ack_sequence[j]["timestamp"] - start_time
                        ).total_seconds() <= 0.2:
                            dup_count += 1
                            j += 1
                        else:
                            break

                    burst_time = (
                        ack_sequence[j - 1]["timestamp"] - start_time
                    ).total_seconds()

                    if burst_time <= 0.2:
                        retrans_events.append({
                            "timestamp": start_time,
                            "flow": (
                                f"{flow[0]}:{flow[2]} -> {flow[1]}:{flow[3]}"
                            ),
                            "ack_number": ack_num,
                            "duplicate_count": dup_count,
                            "severity": "High" if dup_count >= 3 else "Low",
                            "time_window_ms": round(burst_time * 1000, 2)
                        })

                    i = j
                else:
                    i += 1

        df = pd.DataFrame(retrans_events)

        if df.empty:
            return {}

        return {
            "dataframe": df,
            "statistics": {
                "total_bursts": len(df),
                "mean_duplicates_per_burst": df["duplicate_count"].mean(),
                "high_severity_bursts": len(df[df["severity"] == "High"])
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
            .sort_values("timestamp")
            .reset_index(drop=True)
        )

        syn_tracker = {}
        half_open = []

        for _, pkt in packets.iterrows():
            flags = str(pkt["flags"])
            src_ip = pkt["src_ip"]
            dst_ip = pkt["dst_ip"]
            src_port = pkt["src_port"]
            dst_port = pkt["dst_port"]
            timestamp = pkt["timestamp"]

            flow_key = (src_ip, src_port, dst_ip, dst_port)
            reverse_key = (dst_ip, dst_port, src_ip, src_port)

            if "S" in flags and "A" not in flags:
                syn_tracker[flow_key] = {
                    "timestamp": timestamp,
                    "synack_seen": False,
                    "ack_seen": False
                }

            elif "S" in flags and "A" in flags:
                if reverse_key in syn_tracker:
                    syn_tracker[reverse_key]["synack_seen"] = True

            elif "A" in flags and "S" not in flags:
                if flow_key in syn_tracker:
                    syn_tracker[flow_key]["ack_seen"] = True

        for flow_key, state in syn_tracker.items():
            syn_time = state["timestamp"]
            synack_seen = state["synack_seen"]
            ack_seen = state["ack_seen"]
            src_ip, src_port, dst_ip, dst_port = flow_key

            if not synack_seen:
                half_open.append({
                    "timestamp": syn_time,
                    "flow": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "issue": "SYN without SYNACK",
                    "severity": "High"
                })
            elif synack_seen and not ack_seen:
                half_open.append({
                    "timestamp": syn_time,
                    "flow": f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "issue": "SYNACK received but no ACK",
                    "severity": "Medium"
                })

        df = pd.DataFrame(half_open)

        if df.empty:
            return {}

        return {
            "dataframe": df,
            "statistics": {
                "total_half_open": len(df),
                "unique_flows": df["flow"].nunique(),
                "severity_distribution": {
                    "high": len(df[df["severity"] == "High"]),
                    "medium": len(df[df["severity"] == "Medium"])
                },
                "note": (
                    "Half-open connections are rare in normal traffic. "
                    "High counts suggest port scanning or network issues."
                )
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