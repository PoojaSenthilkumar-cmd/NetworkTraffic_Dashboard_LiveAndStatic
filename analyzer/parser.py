"""
parser.py
Optimized PCAP parser for large datasets
Uses streaming packet reading for better performance.
"""

from scapy.all import (
    PcapReader,
    IP,
    TCP,
    UDP,
    ICMP
)

import pandas as pd
import logging

logger = logging.getLogger(__name__)


class PcapParser:
    """
    Parse PCAP file efficiently using streaming.
    """

    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.df = None

    def parse(self):
        """
        Parse PCAP file packet-by-packet.
        Optimized for large files.
        """

        packet_data = []

        try:
            with PcapReader(self.pcap_file) as packets:

                for idx, pkt in enumerate(packets):

                    try:
                        packet_info = {
                            "packet_id": idx,
                            "timestamp": float(pkt.time),
                            "size": int(len(pkt)),
                            "src_ip": None,
                            "dst_ip": None,
                            "src_port": None,
                            "dst_port": None,
                            "protocol": "OTHER",
                            "flags": "",
                            "seq_num": None,
                            "ack_num": None,
                            "payload_size": 0
                        }

                        # Only IP traffic
                        if IP in pkt:
                            ip_layer = pkt[IP]

                            packet_info["src_ip"] = str(ip_layer.src)
                            packet_info["dst_ip"] = str(ip_layer.dst)

                            # ---------------- TCP ----------------
                            if TCP in pkt:
                                tcp = pkt[TCP]

                                packet_info["protocol"] = "TCP"
                                packet_info["src_port"] = int(tcp.sport)
                                packet_info["dst_port"] = int(tcp.dport)

                                # convert to string → avoids pyarrow error
                                packet_info["flags"] = str(tcp.flags)

                                packet_info["seq_num"] = (
                                    int(tcp.seq)
                                    if tcp.seq is not None
                                    else None
                                )

                                packet_info["ack_num"] = (
                                    int(tcp.ack)
                                    if tcp.ack is not None
                                    else None
                                )

                                payload = bytes(tcp.payload)
                                packet_info["payload_size"] = len(payload)

                            # ---------------- UDP ----------------
                            elif UDP in pkt:
                                udp = pkt[UDP]

                                packet_info["protocol"] = "UDP"
                                packet_info["src_port"] = int(udp.sport)
                                packet_info["dst_port"] = int(udp.dport)

                            # ---------------- ICMP ----------------
                            elif ICMP in pkt:
                                packet_info["protocol"] = "ICMP"

                        packet_data.append(packet_info)

                        # Progress log every 50k packets
                        if idx % 50000 == 0 and idx > 0:
                            logger.info(
                                f"Processed {idx:,} packets..."
                            )

                    except Exception:
                        continue

            df = pd.DataFrame(packet_data)

            if df.empty:
                return pd.DataFrame()

            # Convert timestamp safely
            df["timestamp"] = pd.to_datetime(
                df["timestamp"],
                unit="s",
                errors="coerce"
            )

            # Remove invalid timestamps
            df = df.dropna(subset=["timestamp"])

            # Fill missing safely
            df["src_port"] = (
                df["src_port"]
                .fillna(0)
                .astype(int)
            )

            df["dst_port"] = (
                df["dst_port"]
                .fillna(0)
                .astype(int)
            )

            df["size"] = (
                df["size"]
                .fillna(0)
                .astype(int)
            )

            # Prevent Arrow errors
            object_cols = [
                "src_ip",
                "dst_ip",
                "protocol",
                "flags"
            ]

            for col in object_cols:
                df[col] = (
                    df[col]
                    .fillna("")
                    .astype(str)
                )

            logger.info(
                f"Loaded {len(df):,} packets"
            )

            self.df = df
            return df

        except Exception as e:
            logger.error(f"Parser Error: {e}")
            return pd.DataFrame()

    def get_dataframe(self):
        return self.df if self.df is not None else self.parse()


def load_pcap(pcap_file):
    parser = PcapParser(pcap_file)
    return parser.parse()