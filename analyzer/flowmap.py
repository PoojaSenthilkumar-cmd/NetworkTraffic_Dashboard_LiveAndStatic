"""
flowmap.py
Network flow mapping.
"""

import pandas as pd
import ipaddress


class FlowMapper:

    def __init__(self, packets_df):

        self.df = packets_df.copy()

        self.flow_map = None

    def analyze(self):

        if self.df.empty:
            return {}

        packets = self.df[
            (
                self.df["src_ip"]
                != ""
            )
            &
            (
                self.df["dst_ip"]
                != ""
            )
        ].copy()

        flows = packets.groupby([
            "src_ip",
            "dst_ip",
            "protocol",
            "src_port",
            "dst_port"
        ])

        flow_results = []

        for flow, group in flows:

            (
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port
            ) = flow

            packet_count = len(group)

            total_bytes = (
                group["size"]
                .sum()
            )

            start = (
                group[
                    "timestamp"
                ].min()
            )

            end = (
                group[
                    "timestamp"
                ].max()
            )

            latency_ms = (
                end - start
            ).total_seconds() * 1000

            if latency_ms > 0:
                throughput = (
                    total_bytes
                    * 8
                ) / (
                    latency_ms
                    / 1000
                    * 1_000_000
                )
            else:
                throughput = 0

            traffic_type = (
                self._traffic_type(
                    src_ip,
                    dst_ip
                )
            )

            service = (
                self._identify_service(
                    dst_port
                )
            )

            flow_results.append({
                "src_ip":
                    src_ip,
                "dst_ip":
                    dst_ip,
                "protocol":
                    protocol,
                "src_port":
                    src_port,
                "dst_port":
                    dst_port,
                "packet_count":
                    packet_count,
                "total_bytes":
                    total_bytes,
                "latency_ms":
                    latency_ms,
                "throughput_mbps":
                    throughput,
                "traffic_type":
                    traffic_type,
                "service":
                    service
            })

        self.flow_map = pd.DataFrame(
            flow_results
        )

        return {
            "dataframe":
                self.flow_map,
            "statistics":
                self._statistics()
        }

    # ---------------------------------
    # Traffic classification
    # ---------------------------------

    def _traffic_type(
        self,
        src_ip,
        dst_ip
    ):

        src_internal = (
            self._is_private_ip(
                src_ip
            )
        )

        dst_internal = (
            self._is_private_ip(
                dst_ip
            )
        )

        if (
            src_internal
            and dst_internal
        ):
            return "Within College"

        return "Outside College"

    def _is_private_ip(
        self,
        ip
    ):

        try:
            return (
                ipaddress.ip_address(
                    ip
                ).is_private
            )
        except:
            return False

    # ---------------------------------
    # Service Detection
    # ---------------------------------

    def _identify_service(
        self,
        port
    ):

        service_map = {
            80: "HTTP",
            443: "HTTPS",
            53: "DNS",
            22: "SSH",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            3306: "MySQL",
            8080: "HTTP Alt"
        }

        return service_map.get(
            port,
            f"Port {port}"
        )

    # ---------------------------------
    # Statistics
    # ---------------------------------

    def _statistics(self):

        df = self.flow_map

        return {
            "total_flows":
                len(df),

            "internal_flows":
                len(
                    df[
                        df[
                            "traffic_type"
                        ]
                        ==
                        "Within College"
                    ]
                ),

            "external_flows":
                len(
                    df[
                        df[
                            "traffic_type"
                        ]
                        ==
                        "Outside College"
                    ]
                ),

            "total_bytes":
                df[
                    "total_bytes"
                ].sum(),

            "avg_latency_ms":
                df[
                    "latency_ms"
                ].mean()
        }