"""
flowmap.py
Network flow mapping.
"""

import pandas as pd
import ipaddress


class FlowMapper:

    def __init__(self, packets_df, rtt_data=None):
        self.df = packets_df.copy()
        self.rtt_data = rtt_data
        self.flow_map = None

    def analyze(self):

        if self.df.empty:
            return {}

        packets = self.df[
            (self.df["src_ip"] != "") &
            (self.df["dst_ip"] != "")
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
            src_ip, dst_ip, protocol, src_port, dst_port = flow
            packet_count = len(group)
            total_bytes = group["size"].sum()
            start = group["timestamp"].min()
            end = group["timestamp"].max()
            duration_sec = (end - start).total_seconds()

            if duration_sec > 0:
                throughput_mbps = (total_bytes * 8) / (duration_sec * 1_000_000)
            else:
                throughput_mbps = 0

            latency_ms = self._get_latency_for_flow(
                src_ip, dst_ip, src_port, dst_port, protocol
            )

            traffic_type = self._traffic_type(src_ip, dst_ip)
            service = self._identify_service(dst_port)

            flow_results.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "packet_count": packet_count,
                "total_bytes": total_bytes,
                "latency_ms": latency_ms,
                "flow_duration_sec": duration_sec,
                "throughput_mbps": throughput_mbps,
                "traffic_type": traffic_type,
                "service": service
            })

        self.flow_map = pd.DataFrame(flow_results)

        return {
            "dataframe": self.flow_map,
            "statistics": self._statistics()
        }

    def _get_latency_for_flow(self, src_ip, dst_ip, src_port, dst_port, protocol):
        if self.rtt_data is not None and not self.rtt_data.empty:
            flow_rtts = self.rtt_data[
                (self.rtt_data["src_ip"] == src_ip) &
                (self.rtt_data["dst_ip"] == dst_ip)
            ]["rtt_ms"]

            if len(flow_rtts) > 0:
                return round(flow_rtts.mean(), 2)

        if protocol == "TCP":
            synack_rtt = self._estimate_rtt_from_tcp()
            if synack_rtt:
                return synack_rtt

        return 0

    def _estimate_rtt_from_tcp(self):
        try:
            tcp = self.df[self.df["protocol"] == "TCP"].sort_values("timestamp")
            if len(tcp) < 2:
                return 0

            for idx, row in tcp.iterrows():
                flags = str(row["flags"])
                if "S" in flags and "A" not in flags:
                    syn_time = row["timestamp"]
                    future_packets = tcp[tcp["timestamp"] > syn_time].head(10)
                    for _, p in future_packets.iterrows():
                        if "S" in str(p["flags"]) and "A" in str(p["flags"]):
                            synack_time = p["timestamp"]
                            rtt = (synack_time - syn_time).total_seconds() * 1000
                            if 0 < rtt < 5000:
                                return round(rtt, 2)
            return 0
        except Exception:
            return 0

    # ---------------------------------
    # Traffic classification
    # ---------------------------------

    def _traffic_type(self, src_ip, dst_ip):

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
            "total_flows": len(df),
            "internal_flows": len(df[df["traffic_type"] == "Within College"]),
            "external_flows": len(df[df["traffic_type"] == "Outside College"]),
            "total_bytes": df["total_bytes"].sum(),
            "avg_latency_ms": df["latency_ms"].mean(),
            "max_latency_ms": df["latency_ms"].max(),
            "avg_flow_duration_sec": df["flow_duration_sec"].mean()
        }