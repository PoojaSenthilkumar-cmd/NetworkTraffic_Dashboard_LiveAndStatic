"""
parser_optimized.py
Optimized PCAP parser for very large files (>200MB)
Implements chunked processing with progress tracking to minimize memory footprint.
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


class OptimizedPcapParser:
    """
    Parse large PCAP files with chunked processing.
    Prevents loading entire file into memory at once.
    """

    def __init__(self, pcap_file, chunk_size=50000):
        """
        Initialize parser with configurable chunk size.
        
        Args:
            pcap_file: Path to PCAP file
            chunk_size: Number of packets to process before consolidating chunk
        """
        self.pcap_file = pcap_file
        self.chunk_size = chunk_size
        self.df = None
        self.total_packets_processed = 0

    def _extract_packet_info(self, pkt, idx):
        """Extract packet information from scapy packet object."""
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

            # TCP
            if TCP in pkt:
                tcp = pkt[TCP]
                packet_info["protocol"] = "TCP"
                packet_info["src_port"] = int(tcp.sport)
                packet_info["dst_port"] = int(tcp.dport)
                packet_info["flags"] = str(tcp.flags)
                packet_info["seq_num"] = (
                    int(tcp.seq) if tcp.seq is not None else None
                )
                packet_info["ack_num"] = (
                    int(tcp.ack) if tcp.ack is not None else None
                )
                payload = bytes(tcp.payload)
                packet_info["payload_size"] = len(payload)

            # UDP
            elif UDP in pkt:
                udp = pkt[UDP]
                packet_info["protocol"] = "UDP"
                packet_info["src_port"] = int(udp.sport)
                packet_info["dst_port"] = int(udp.dport)

            # ICMP
            elif ICMP in pkt:
                packet_info["protocol"] = "ICMP"

        return packet_info

    def _process_chunk(self, chunk_df):
        """Apply data type conversions and cleaning to a chunk."""
        if chunk_df.empty:
            return chunk_df

        # Convert timestamp safely
        chunk_df["timestamp"] = pd.to_datetime(
            chunk_df["timestamp"],
            unit="s",
            errors="coerce"
        )

        # Remove invalid timestamps
        chunk_df = chunk_df.dropna(subset=["timestamp"])

        # Fill missing values safely
        chunk_df["src_port"] = (
            chunk_df["src_port"].fillna(0).astype(int)
        )
        chunk_df["dst_port"] = (
            chunk_df["dst_port"].fillna(0).astype(int)
        )
        chunk_df["size"] = (
            chunk_df["size"].fillna(0).astype(int)
        )

        # Prevent Arrow serialization errors
        object_cols = ["src_ip", "dst_ip", "protocol", "flags"]
        for col in object_cols:
            chunk_df[col] = (
                chunk_df[col].fillna("").astype(str)
            )

        return chunk_df

    def parse_chunked(self, progress_callback=None):
        """
        Parse PCAP file in chunks with progress tracking.
        
        Args:
            progress_callback: Optional callable(packet_count) for progress updates
            
        Returns:
            DataFrame with all parsed packets
        """
        all_chunks = []
        chunk_data = []
        idx = 0
        total_packets = 0

        try:
            with PcapReader(self.pcap_file) as packets:
                for pkt in packets:
                    try:
                        packet_info = self._extract_packet_info(pkt, idx)
                        chunk_data.append(packet_info)
                        idx += 1
                        total_packets += 1

                        # Process chunk when it reaches target size
                        if len(chunk_data) >= self.chunk_size:
                            chunk_df = pd.DataFrame(chunk_data)
                            chunk_df = self._process_chunk(chunk_df)
                            all_chunks.append(chunk_df)

                            # Call progress callback if provided
                            if progress_callback:
                                progress_callback(total_packets)

                            logger.info(
                                f"Processed chunk: {total_packets:,} packets total"
                            )

                            chunk_data = []

                    except Exception as e:
                        logger.debug(f"Skipped packet: {e}")
                        continue

                # Process final chunk
                if chunk_data:
                    chunk_df = pd.DataFrame(chunk_data)
                    chunk_df = self._process_chunk(chunk_df)
                    all_chunks.append(chunk_df)
                    
                    if progress_callback:
                        progress_callback(total_packets)

            # Combine all chunks
            if all_chunks:
                df = pd.concat(all_chunks, ignore_index=True)
            else:
                df = pd.DataFrame()

            self.total_packets_processed = len(df)
            logger.info(
                f"Completed parsing: {self.total_packets_processed:,} total packets"
            )

            self.df = df
            return df

        except Exception as e:
            logger.error(f"Parser Error: {e}")
            return pd.DataFrame()

    def parse(self):
        """
        Legacy method for backward compatibility.
        Calls parse_chunked without progress callback.
        """
        return self.parse_chunked(progress_callback=None)

    def get_dataframe(self):
        """Return cached dataframe or parse if not available."""
        return self.df if self.df is not None else self.parse()


def load_pcap_optimized(pcap_file, chunk_size=50000, progress_callback=None):
    """
    Convenience function to load PCAP with chunked processing.
    
    Args:
        pcap_file: Path to PCAP file
        chunk_size: Packets per chunk
        progress_callback: Optional progress callback
        
    Returns:
        DataFrame with parsed packets
    """
    parser = OptimizedPcapParser(pcap_file, chunk_size=chunk_size)
    return parser.parse_chunked(progress_callback=progress_callback)
