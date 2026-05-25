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
from analyzer.throughput import (ACCEPTABLE_THRESHOLD_MBPS, ThroughputAnalyzer)
from analyzer.flowmap import (FlowMapper)

from liveCaptureData.live_capture import (LiveCaptureManager)


CAPTURED_THROUGHPUT_WINDOW_MS = 5000
LIVE_CAPTURE_PACKET_LIMIT = 0

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
    packets_df,
    throughput_window=5000
):

    results = {}

    # RTT
    rtt_result = RTTAnalyzer(packets_df).analyze()
    results["rtt"] = rtt_result
    rtt_df = rtt_result.get("dataframe", pd.DataFrame()) if rtt_result else pd.DataFrame()

    # Jitter
    results["jitter"] = JitterAnalyzer(packets_df).analyze()

    # Reordering
    results["reordering"] = ReorderingAnalyzer(packets_df).analyze()

    # TCP
    results["tcp"] = TCPAnalyzer(packets_df).get_all_tcp_analysis()

    # Throughput
    results["throughput"] = ThroughputAnalyzer(packets_df).analyze(time_window_ms=throughput_window)

    # Flow map
    results["flowmap"] = FlowMapper(packets_df, rtt_data=rtt_df).analyze()

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

    fig = px.bar(
        jitter_df,
        x="flow",
        y="jitter_ms_rfc3550",
        title="Jitter by Flow (RFC 3550)"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


# ==========================================
# Throughput Plot
# ==========================================

def plot_throughput(
    throughput_df,
    stability_metric=None
):

    if throughput_df.empty:
        st.warning(
            "No throughput data"
        )
        st.caption(
            "Throughput analysis returned an empty dataframe. Check that packets include timestamp and size values."
        )
        return

    required_columns = {
        "timestamp",
        "throughput_mbps"
    }
    missing_columns = required_columns - set(throughput_df.columns)
    if missing_columns:
        st.warning(
            f"Throughput data is missing required column(s): {', '.join(sorted(missing_columns))}"
        )
        st.caption(
            f"Available columns: {', '.join(throughput_df.columns)}"
        )
        return

    plot_df = throughput_df.dropna(
        subset=[
            "timestamp",
            "throughput_mbps"
        ]
    ).copy()

    if plot_df.empty:
        st.warning(
            "No plottable throughput datapoints"
        )
        st.caption(
            "All throughput rows are missing timestamp or throughput_mbps values."
        )
        return

    classification = (
        stability_metric or {}
    ).get("stability_classification", "Stable")

    fig = px.line(
        plot_df,
        x="timestamp",
        y="throughput_mbps",
        title=f"Throughput Stability - {classification}",
        markers=True
    )

    fig.add_hline(
        y=ACCEPTABLE_THRESHOLD_MBPS,
        line_dash="dash",
        line_color="red",
        annotation_text=f"Acceptable threshold ({ACCEPTABLE_THRESHOLD_MBPS:.1f} Mbps)",
        annotation_position="top left"
    )

    abnormal_points = plot_df[
        plot_df["throughput_mbps"] > ACCEPTABLE_THRESHOLD_MBPS
    ]

    if not abnormal_points.empty:
        fig.add_trace(
            go.Scatter(
                x=abnormal_points["timestamp"],
                y=abnormal_points["throughput_mbps"],
                mode="markers",
                marker=dict(color="red", size=9),
                name="Abnormal burst"
            )
        )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


def compare_rtt_vs_jitter(rtt_df, jitter_df):
    return {
        "rtt_metrics": {
            "mean_ms": rtt_df["rtt_ms"].mean(),
            "std_ms": rtt_df["rtt_ms"].std(),
            "min_ms": rtt_df["rtt_ms"].min(),
            "max_ms": rtt_df["rtt_ms"].max(),
            "explanation": "RTT measures round-trip latency for packet pairs."
        },
        "jitter_metrics": {
            "mean_ms": jitter_df["jitter_ms_rfc3550"].mean(),
            "std_ms": jitter_df["jitter_ms_rfc3550"].std(),
            "min_ms": jitter_df["jitter_ms_rfc3550"].min(),
            "max_ms": jitter_df["jitter_ms_rfc3550"].max(),
            "explanation": "Jitter measures variance in packet arrival spacing over time."
        }
    }


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
        stability_metric = throughput.get("stability_metric", {})
        stability = stability_metric.get("stability_classification")
        is_burst_event = stability_metric.get("is_burst_event", False)

        if is_burst_event or stability in [
            "Moderate Variability",
            "High Variability"
        ]:
            events.append(
                (
                    "Throughput Variability",
                    stability or "Anomalous"
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

    throughput_window = CAPTURED_THROUGHPUT_WINDOW_MS
    analysis_config_key = {
        "mode": mode,
        "throughput_window": throughput_window
    }

    packets_df = None

    # ======================================
    # CAPTURED TRAFFIC
    # ======================================

    if mode == (
        "Captured Traffic"
    ):

        throughput_window = CAPTURED_THROUGHPUT_WINDOW_MS

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

        selected_time_window = (
            st.sidebar.slider(
                "Time Window (seconds)",
                10,
                300,
                60
            )
        )

        capture_timeout = selected_time_window
        # Live slider controls capture duration; throughput analyzer expects a millisecond bucket size.
        throughput_window = CAPTURED_THROUGHPUT_WINDOW_MS
        analysis_config_key = {
            "mode": mode,
            "capture_timeout": capture_timeout,
            "throughput_window": throughput_window
        }

        if st.sidebar.button(
            "Start Capture"
        ):

            st.session_state.analysis_results = None

            manager = (
                LiveCaptureManager()
            )

            capture = (
                manager
                .start_new_capture(
                    "session1",

                    packet_count=
                    LIVE_CAPTURE_PACKET_LIMIT,
                    capture_timeout=
                    capture_timeout
                )
            )

            progress = (
                st.progress(0)
            )

            capture_started_at = time.time()

            while (
                capture
                .is_capturing()
            ):

                progress.progress(
                    min(
                        (time.time() - capture_started_at)
                        /
                        capture_timeout,
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

    if (
        'analysis_config_key' not in st.session_state
        or st.session_state.analysis_config_key != analysis_config_key
    ):
        st.session_state.analysis_config_key = analysis_config_key
        st.session_state.analysis_results = None

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
                    st.session_state.analysis_results = run_analysis(
                        packets_df,
                        throughput_window=throughput_window
                    )

        results = st.session_state.analysis_results
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

            rtt = results["rtt"]
            if rtt:
                rtt_df = rtt["dataframe"]
                rtt_stats = rtt["statistics"]

                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric(
                        "Mean RTT",
                        f"{rtt_stats['mean_rtt']:.2f} ms",
                    )
                with col2:
                    st.metric("Median RTT", f"{rtt_stats['median_rtt']:.2f} ms")
                with col3:
                    st.metric("Max RTT", f"{rtt_stats['max_rtt']:.2f} ms")
                with col4:
                    st.metric("RTT Samples", f"{rtt_stats['count']}")

                plot_rtt(rtt_df)

            st.markdown("---")

            st.subheader(
                "Jitter Analysis"
            )

            jitter = results["jitter"]
            if jitter:
                jitter_df = jitter["dataframe"]
                jitter_stats = jitter["statistics"]

                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric(
                        "Mean Jitter",
                        f"{jitter_stats['mean_jitter_ms']:.2f} ms"
                    )
                with col2:
                    st.metric(
                        "Median Jitter",
                        f"{jitter_stats['median_jitter_ms']:.2f} ms"
                    )
                with col3:
                    st.metric(
                        "Max Jitter",
                        f"{jitter_stats['max_jitter_ms']:.2f} ms"
                    )
                with col4:
                    st.metric(
                        "Flows Analyzed",
                        f"{jitter_stats['total_flows']}"
                    )

                plot_jitter(jitter_df)

            if rtt and jitter:
                compare = compare_rtt_vs_jitter(rtt_df, jitter_df)
                st.markdown("---")
                st.subheader("RTT vs Jitter Comparison")

                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("### RTT (Latency)")
                    st.write(f"**Mean:** {compare['rtt_metrics']['mean_ms']:.2f} ms")
                    st.write(f"**Std Dev:** {compare['rtt_metrics']['std_ms']:.2f} ms")
                    st.write(f"**Min:** {compare['rtt_metrics']['min_ms']:.2f} ms")
                    st.write(f"**Max:** {compare['rtt_metrics']['max_ms']:.2f} ms")
                    st.write(compare['rtt_metrics']['explanation'])
                with col2:
                    st.markdown("### Jitter (Variance)")
                    st.write(f"**Mean:** {compare['jitter_metrics']['mean_ms']:.2f} ms")
                    st.write(f"**Std Dev:** {compare['jitter_metrics']['std_ms']:.2f} ms")
                    st.write(f"**Min:** {compare['jitter_metrics']['min_ms']:.2f} ms")
                    st.write(f"**Max:** {compare['jitter_metrics']['max_ms']:.2f} ms")
                    st.write(compare['jitter_metrics']['explanation'])

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

                stability_metric = throughput[
                    "stability_metric"
                ]

                plot_throughput(
                    throughput[
                        "dataframe"
                    ],
                    stability_metric
                )

                st.metric(
                    "Stability",
                    stability_metric[
                        "stability_classification"
                    ]
                )

                if stability_metric.get("is_burst_event"):
                    st.warning(
                        f"⚠️ {stability_metric['anomalies_detected']} abnormal burst(s) detected"
                    )

                if stability_metric.get("is_burst_event"):
                    st.caption(
                        f"Abnormal means throughput above {ACCEPTABLE_THRESHOLD_MBPS:.1f} Mbps."
                    )

                if not stability_metric.get("is_burst_event"):
                    st.success(
                        "Stable throughput within acceptable range"
                    )

                if stability_metric.get("recommendation"):
                    st.write(
                        stability_metric["recommendation"]
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
