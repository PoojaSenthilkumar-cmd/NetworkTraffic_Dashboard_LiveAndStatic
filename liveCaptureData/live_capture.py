"""
live_capture.py
Live network traffic capture using Scapy.
Optimized for Streamlit.
"""

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP
)

import pandas as pd
import threading
from queue import Queue
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class LivePacketCapture:

    def __init__(
        self,
        packet_count=500,
        interface=None,
        capture_timeout=60
    ):

        self.packet_count = packet_count
        self.interface = interface
        self.capture_timeout = capture_timeout

        self.packets = []

        self.packet_queue = Queue()

        self.capture_running = False

        self.capture_thread = None

    # =====================================
    # Packet Callback
    # =====================================

    def packet_callback(
        self,
        packet
    ):

        try:

            packet_info = {
                "timestamp":datetime.now(),
                "size":int(len(packet)),
                "src_ip":"",
                "dst_ip":"",
                "src_port":0,
                "dst_port":0,
                "protocol":"OTHER",
                "flags":"",
                "seq_num":None,
                "ack_num":None,
                "payload_size":0
            }

            if IP in packet:
                ip_layer = packet[IP]
                packet_info["src_ip"] = str(ip_layer.src)
                packet_info["dst_ip"] = str(ip_layer.dst)

                # ---------------- TCP ----------------
                if TCP in packet:
                    tcp = packet[TCP]
                    packet_info["protocol"] = "TCP"
                    packet_info["src_port"] = int(tcp.sport)
                    packet_info["dst_port"] = int(tcp.dport)
                    packet_info["flags"] = str(tcp.flags)
                    packet_info["seq_num"] = (
                        int(tcp.seq)
                        if tcp.seq
                        else None
                    )
                    packet_info["ack_num"] = (
                        int(tcp.ack)
                        if tcp.ack
                        else None
                    )
                    payload = bytes(tcp.payload)
                    packet_info["payload_size"] = len(payload)

                # ---------------- UDP ----------------
                elif UDP in packet:
                    udp = packet[UDP]
                    packet_info["protocol"] = "UDP"
                    packet_info["src_port"] = int(udp.sport)
                    packet_info["dst_port"] = int(udp.dport)

                # ---------------- ICMP ----------------
                elif ICMP in packet:

                    packet_info["protocol"] = "ICMP"

            self.packets.append(packet_info)
            self.packet_queue.put(packet_info)

        except Exception:
            pass

    # =====================================
    # Background Capture
    # =====================================

    def _sniff_background(
        self
    ):

        try:

            sniff(
                prn=self.packet_callback,
                iface=self.interface,
                store=False,
                count=self.packet_count,
                timeout=self.capture_timeout
            )

        except Exception as e:
            logger.error(
                f"Capture Error: {e}"
            )

        finally:
            self.capture_running = (
                False
            )

    # =====================================
    # Start Capture
    # =====================================

    def start_capture(
        self
    ):

        if self.capture_running:
            return False

        self.capture_running = True

        self.packets = []

        self.capture_thread = (
            threading.Thread(
                target=self._sniff_background,
                daemon=True
            )
        )

        self.capture_thread.start()

        return True

    # =====================================
    # Stop Capture
    # =====================================

    def stop_capture(
        self
    ):

        self.capture_running = (
            False
        )

    # =====================================
    # Dataframe
    # =====================================

    def get_packets_dataframe(
        self
    ):

        if not self.packets:
            return pd.DataFrame()

        df = pd.DataFrame(
            self.packets
        )

        df[
            "timestamp"
        ] = pd.to_datetime(
            df[
                "timestamp"
            ]
        )

        return df

    # =====================================
    # Stats
    # =====================================

    def get_capture_stats(
        self
    ):

        if not self.packets:
            return {}

        df = pd.DataFrame(
            self.packets
        )

        duration = 0

        if len(df) > 1:

            duration = (
                df["timestamp"].max()  
                - df["timestamp"].min()
            ).total_seconds()

        return {
            "total_packets":len(df),
            "capture_duration":round(duration,2),
            "avg_packet_size":round(df["size"].mean(),2),
            "total_bytes":int(df["size"].sum())
        }

    # =====================================
    # Helper Methods
    # =====================================

    def get_packet_count(self):

        return len(self.packets)

    def is_capturing(self):

        return (self.capture_running)


# ==========================================
# Manager
# ==========================================

class LiveCaptureManager:

    def __init__(self):

        self.captures = {}

    def start_new_capture(
        self,
        session_id,
        packet_count=500,
        interface=None,
        capture_timeout=60
    ):

        capture = (
            LivePacketCapture(
                packet_count=
                packet_count,
                interface=
                interface,
                capture_timeout=
                capture_timeout
            )
        )

        capture.start_capture()

        self.captures[
            session_id
        ] = capture

        return capture

    def get_capture(
        self,
        session_id
    ):

        return self.captures.get(
            session_id
        )

    def stop_capture(
        self,
        session_id
    ):

        if (
            session_id
            in self.captures
        ):

            self.captures[
                session_id
            ].stop_capture()