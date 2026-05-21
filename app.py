"""
app.py
Network Traffic Analysis Dashboard
Supports:
1. Uploaded PCAP Analysis
2. Live Traffic Capture

Features:
- RTT Analysis
- Jitter Analysis
- Packet Reordering
- TCP Slow Start
- Retransmission Bursts
- Half Open Connections
- Throughput Stability
- Flow Mapping
- Causality Analysis
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import tempfile
import time
from datetime import datetime

# ==========================================
# Analyzer Imports
# ==========================================

# from analyzer.parser import PcapParser
from analyzer.parser_optimized import OptimizedPcapParser
from analyzer.rtt import RTTAnalyzer
from analyzer.jitter import JitterAnalyzer
from analyzer.reordering import (ReorderingAnalyzer)
from analyzer.tcp_analysis import (TCPAnalyzer)
from analyzer.throughput import (ThroughputAnalyzer)
from analyzer.flowmap import (FlowMapper)

from liveCaptureData.live_capture import (LiveCaptureManager)

# ==========================================
# Streamlit Config
# ==========================================

st.set_page_config(
    page_title= "Network Traffic Dashboard",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ==========================================
# CSS
# ==========================================

st.markdown(
    """
<style>

.metric-card {
    background-color:
    #f5f5f5;

    padding: 15px;

    border-radius: 10px;

    border:
    1px solid #ddd;
}

.main-header {
    font-size: 35px;
    font-weight: bold;
}

.sub-header {
    font-size: 22px;
    font-weight: bold;
}

</style>
""",
    unsafe_allow_html=True
)

# ==========================================
# SESSION STATE & CACHING
# ==========================================

def initialize_session_state():
    """Initialize session state variables for large file handling."""
    if 'pcap_data' not in st.session_state:
        st.session_state.pcap_data = None
    if 'pcap_file_name' not in st.session_state:
        st.session_state.pcap_file_name = None
    if 'pcap_file_id' not in st.session_state:
        st.session_state.pcap_file_id = None
    if 'analysis_results' not in st.session_state:
        st.session_state.analysis_results = None


def make_file_id(uploaded_file):
    """Create a stable ID for the uploaded file to detect changes."""
    try:
        size = uploaded_file.size
    except Exception:
        size = len(uploaded_file.getvalue())
    return (uploaded_file.name, size)


def load_pcap_with_progress(file_path, file_name):
    """
    Load PCAP file with progress tracking.
    Uses optimized chunked parser for large files.
    
    Args:
        file_path: Path to the PCAP file
        file_name: Display name of the file
        
    Returns:
        DataFrame with parsed packets
    """
    progress_placeholder = st.empty()
    status_placeholder = st.empty()

    parser = OptimizedPcapParser(
        file_path,
        chunk_size=50000
    )

    # Track progress
    def progress_callback(packet_count):
        est_total = max(packet_count, 2_000_000)
        progress = min(packet_count / est_total, 1.0)
        progress_placeholder.progress(progress, text=f"Parsing packets...")
        status_placeholder.text(f"📊 Processed: {packet_count:,} packets")

    # Parse with progress tracking
    packets_df = parser.parse_chunked(progress_callback=progress_callback)

    # Cleanup placeholders
    progress_placeholder.empty()
    status_placeholder.empty()

    return packets_df


@st.cache_data(
    show_spinner=False
)
def run_analysis(
    packets_df
):

    results = {}

    # RTT
    results[
        "rtt"
    ] = (
        RTTAnalyzer(
            packets_df
        ).analyze()
    )

    # Jitter
    results[
        "jitter"
    ] = (
        JitterAnalyzer(
            packets_df
        ).analyze()
    )

    # Reordering
    results[
        "reordering"
    ] = (
        ReorderingAnalyzer(
            packets_df
        ).analyze()
    )

    # TCP
    results[
        "tcp"
    ] = (
        TCPAnalyzer(
            packets_df
        )
        .get_all_tcp_analysis()
    )

    # Throughput
    results[
        "throughput"
    ] = (
        ThroughputAnalyzer(
            packets_df
        ).analyze()
    )

    # Flow map
    results[
        "flowmap"
    ] = (
        FlowMapper(
            packets_df
        ).analyze()
    )

    return results


# ==========================================
# RTT Plot
# ==========================================

def plot_rtt(rtt_df):

    if rtt_df.empty:
        st.warning("No RTT data")
        return

    colors = []

    for rtt in (rtt_df["rtt_ms"]):
        if rtt < 50:
            colors.append("green")
        elif rtt < 100:
            colors.append("orange")
        else:
            colors.append("red")

    fig = go.Figure()

    fig.add_trace(
        go.Scatter(x=rtt_df["timestamp"],y=rtt_df["rtt_ms"],
            mode="markers+lines", 
            marker=dict(
                color=colors,
                size=6
            ),
            name="RTT"
        )
    )

    fig.update_layout(title="RTT Over Time",
                      xaxis_title="Time",
                      yaxis_title="RTT (ms)",
                      height=450
    )

    st.plotly_chart(fig,use_container_width=True)


# ==========================================
# Jitter Plot
# ==========================================

def plot_jitter(
    jitter_df
):

    if jitter_df.empty:
        st.warning(
            "No jitter data"
        )
        return

    fig = px.line(
        jitter_df,

        x="timestamp",

        y="jitter_ms",

        title=
        "Time vs Jitter"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


# ==========================================
# Throughput Plot
# ==========================================

def plot_throughput(
    throughput_df
):

    if throughput_df.empty:
        st.warning(
            "No throughput data"
        )
        return

    fig = px.line(
        throughput_df,

        x="timestamp",

        y=
        "throughput_mbps",

        title=
        "Throughput Stability"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


# ==========================================
# Reordering Plot
# ==========================================

def plot_reordering(
    reorder_df
):

    if reorder_df.empty:
        st.info(
            "No packet reordering"
        )
        return

    reorder_freq = (
        reorder_df
        .set_index(
            "timestamp"
        )
        .resample("1s")
        .size()
    )

    fig = px.bar(
        x=
        reorder_freq.index,

        y=
        reorder_freq.values,

        labels={
            "x":
            "Time",

            "y":
            "Reordering Events"
        },

        title=
        "Packet Reordering Frequency"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    # ==========================================
# CAUSALITY ANALYSIS
# ==========================================

def show_causality(results):

    st.subheader(
        "Network Behavior & Causality"
    )

    events = []

    # RTT spikes
    rtt = results.get(
        "rtt", {}
    )

    if (
        rtt
        and not rtt[
            "dataframe"
        ].empty
    ):

        high_rtt = rtt[
            "dataframe"
        ][
            rtt[
                "dataframe"
            ][
                "rtt_ms"
            ] > 100
        ]

        if len(high_rtt) > 0:
            events.append(
                (
                    "High RTT Spike",
                    len(high_rtt)
                )
            )

    # retransmission bursts
    tcp = results.get(
        "tcp", {}
    )

    retrans = tcp.get(
        "retransmission",
        {}
    )

    if (
        retrans
        and "dataframe"
        in retrans
    ):

        if not retrans[
            "dataframe"
        ].empty:

            events.append(
                (
                    "Retransmission Bursts",
                    len(
                        retrans[
                            "dataframe"
                        ]
                    )
                )
            )

    # reordering
    reorder = results.get(
        "reordering",
        {}
    )

    if (
        reorder
        and not reorder[
            "dataframe"
        ].empty
    ):

        events.append(
            (
                "Packet Reordering",
                len(
                    reorder[
                        "dataframe"
                    ]
                )
            )
        )

    # throughput instability
    throughput = results.get(
        "throughput",
        {}
    )

    if throughput:

        stability = throughput[
            "stability_metric"
        ][
            "stability_classification"
        ]

        if stability in [
            "Moderate",
            "Unstable"
        ]:

            events.append(
                (
                    "Throughput Instability",
                    stability
                )
            )

    if events:

        st.warning(
            """
Possible Traffic Causality:

Retransmission Burst
→ RTT Increase
→ Throughput Drop
→ Packet Reordering
"""
        )

        st.dataframe(
            pd.DataFrame(
                events,
                columns=[
                    "Behavior",
                    "Count/State"
                ]
            )
        )

    else:

        st.success(
            """
No major
network anomalies
detected.
"""
        )


# ==========================================
# MAIN APP
# ==========================================

def main():

    # Initialize session state for large file handling
    initialize_session_state()

    st.markdown(
        """
<div class='main-header'>
🌐 Network Traffic
Analysis Dashboard
</div>
""",
        unsafe_allow_html=True
    )

    st.markdown("---")

    # ======================================
    # SIDEBAR
    # ======================================

    st.sidebar.title(
        "Configuration"
    )

    mode = (
        st.sidebar.radio(
            "Choose Mode",

            [
                "Captured Traffic",
                "Live Traffic"
            ]
        )
    )

    packets_df = None

    # ======================================
    # CAPTURED TRAFFIC
    # ======================================

    if mode == (
        "Captured Traffic"
    ):

        uploaded_file = (
            st.sidebar.file_uploader(
                "Upload PCAP",

                type=[
                    "pcap",
                    "pcapng"
                ]
            )
        )

        if uploaded_file:
            
            # Show file size info
            file_size_mb = len(uploaded_file.getvalue()) / (1024 * 1024)
            
            if file_size_mb > 1024:
                st.sidebar.info(
                    f"📁 Large file detected: {file_size_mb:.1f} MB "
                    f"({file_size_mb/1024:.2f} GB)\n"
                    f"Using optimized chunked parser..."
                )
            else:
                st.sidebar.info(f"📁 File size: {file_size_mb:.1f} MB")

            file_id = make_file_id(uploaded_file)
            is_same_file = (
                st.session_state.pcap_file_id == file_id
                and st.session_state.pcap_data is not None
            )

            if is_same_file:
                st.sidebar.success(
                    "✅ Using previously parsed PCAP data from this session."
                )
                packets_df = st.session_state.pcap_data
            else:
                # Store a new uploaded file id and clear any old analysis
                st.session_state.pcap_file_id = file_id
                st.session_state.analysis_results = None

                temp_file = (
                    tempfile
                    .NamedTemporaryFile(
                        delete=False,
                        suffix=".pcap"
                    )
                )

                temp_file.write(
                    uploaded_file
                    .getvalue()
                )

                temp_file.close()

                st.info("⏳ Parsing PCAP file with chunked processing...")
                packets_df = load_pcap_with_progress(
                    temp_file.name,
                    uploaded_file.name
                )

                st.session_state.pcap_data = packets_df
                st.session_state.pcap_file_name = uploaded_file.name

        elif st.session_state.pcap_data is not None:
            packets_df = st.session_state.pcap_data

    # ======================================
    # LIVE TRAFFIC
    # ======================================

    else:

        packet_count = (
            st.sidebar.slider(
                "Packets",
                100,
                5000,
                1000
            )
        )

        capture_timeout = (
            st.sidebar.slider(
                "Capture Duration (seconds)",
                10,
                5 * 60,
                60,
                step=10
            )
        )

        if st.sidebar.button(
            "Start Capture"
        ):

            manager = (
                LiveCaptureManager()
            )

            capture = (
                manager
                .start_new_capture(
                    "session1",

                    packet_count=
                    packet_count,
                    capture_timeout=
                    capture_timeout
                )
            )

            progress = (
                st.progress(0)
            )

            while (
                capture
                .is_capturing()
            ):

                packet_num = (
                    capture
                    .get_packet_count()
                )

                progress.progress(
                    min(
                        packet_num
                        /
                        packet_count,
                        1.0
                    )
                )

                time.sleep(
                    0.5
                )

            packets_df = (
                capture
                .get_packets_dataframe()
            )

            st.success(
                "Capture complete"
            )

    # ======================================
    # ANALYSIS
    # ======================================

    if packets_df is not None:

        if packets_df.empty:

            st.error(
                """
No packets found.
"""
            )

            return

        st.success(
            f"""
Loaded
{len(packets_df):,}
packets
"""
        )

        if st.session_state.analysis_results is None:
            with st.spinner(
                "Running Analysis..."
            ):
                st.session_state.analysis_results = run_analysis(packets_df)

        results = st.session_state.analysis_results

        # ==================================
        # METRICS
        # ==================================

        col1, col2, col3 = (
            st.columns(3)
        )

        with col1:

            st.metric(
                "Packets",
                len(
                    packets_df
                )
            )

        with col2:

            tcp_packets = (
                len(
                    packets_df[
                        packets_df[
                            "protocol"
                        ]
                        ==
                        "TCP"
                    ]
                )
            )

            st.metric(
                "TCP Packets",
                tcp_packets
            )

        with col3:

            st.metric(
                "Unique Flows",

                results[
                    "flowmap"
                ][
                    "statistics"
                ][
                    "total_flows"
                ]
            )

        # ==================================
        # TABS
        # ==================================

        tabs = st.tabs([

            "RTT & Jitter",

            "TCP Analysis",

            "Throughput",

            "Flow Map",

            "Causality",

            "Export"
        ])

        # ==================================
        # TAB 1
        # ==================================

        with tabs[0]:

            st.subheader(
                "RTT Analysis"
            )

            rtt = results[
                "rtt"
            ]

            if rtt:

                plot_rtt(
                    rtt[
                        "dataframe"
                    ]
                )

            st.markdown(
                "---"
            )

            st.subheader(
                "Jitter Analysis"
            )

            jitter = results[
                "jitter"
            ]

            if jitter:

                plot_jitter(
                    jitter[
                        "dataframe"
                    ]
                )

        # ==================================
        # TAB 2
        # ==================================

        with tabs[1]:

            tcp = results[
                "tcp"
            ]

            st.subheader(
                """
TCP Slow Start
"""
            )

            if tcp.get(
                "slow_start"
            ):

                st.dataframe(
                    tcp[
                        "slow_start"
                    ][
                        "dataframe"
                    ]
                )

            st.subheader(
                """
Retransmission
Bursts
"""
            )

            if tcp.get(
                "retransmission"
            ):

                st.dataframe(
                    tcp[
                        "retransmission"
                    ][
                        "dataframe"
                    ]
                )

            st.subheader(
                """
Half Open
Connections
"""
            )

            if tcp.get(
                "half_open"
            ):

                st.dataframe(
                    tcp[
                        "half_open"
                    ][
                        "dataframe"
                    ]
                )

        # ==================================
        # TAB 3
        # ==================================

        with tabs[2]:

            throughput = (
                results[
                    "throughput"
                ]
            )

            if throughput:

                plot_throughput(
                    throughput[
                        "dataframe"
                    ]
                )

                st.metric(
                    "Stability",

                    throughput[
                        "stability_metric"
                    ][
                        "stability_classification"
                    ]
                )

        # ==================================
        # TAB 4
        # ==================================

        with tabs[3]:

            flowmap = (
                results[
                    "flowmap"
                ]
            )

            st.dataframe(
                flowmap[
                    "dataframe"
                ],

                use_container_width=
                True
            )

        # ==================================
        # TAB 5
        # ==================================

        with tabs[4]:

            show_causality(
                results
            )

        # ==================================
        # TAB 6
        # ==================================

        with tabs[5]:

            for key in [
                "rtt",
                "jitter",
                "reordering",
                "throughput",
                "flowmap"
            ]:

                if (
                    key
                    in results
                ):

                    result = (
                        results[
                            key
                        ]
                    )

                    if (
                        result
                        and
                        "dataframe"
                        in result
                    ):

                        csv = (
                            result[
                                "dataframe"
                            ]
                            .to_csv(
                                index=False
                            )
                        )

                        st.download_button(
                            label=
                            f"Download {key}",

                            data=csv,

                            file_name=
                            f"{key}.csv",

                            mime=
                            "text/csv"
                        )


# ==========================================
# RUN APP
# ==========================================

if __name__ == "__main__":
    main()