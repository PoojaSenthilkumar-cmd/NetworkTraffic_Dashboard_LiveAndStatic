# APP.PY INTEGRATION GUIDE
## How to Use All Corrected Modules Together

---

## 📝 CORRECTED APP.PY STRUCTURE

```python
"""
app.py - CORRECTED VERSION
Streamlit dashboard using fixed analyzer modules

Key changes:
1. Pass RTT data to FlowMapper (not done before)
2. Separate stability from anomalies in throughput display
3. Verify duplicate ACK counts are reasonable
4. Display RTT and Jitter as separate metrics
5. Flag half-open connections appropriately
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import logging

# Import CORRECTED modules
from analyzer.parser_optimized import OptimizedPcapParser
from analyzer.rtt import RTTAnalyzer
from analyzer.jitter import JitterAnalyzer, compare_rtt_vs_jitter
from analyzer.throughput import ThroughputAnalyzer
from analyzer.tcp_analysis import TCPAnalyzer
from analyzer.flowmap import FlowMapper

logger = logging.getLogger(__name__)

# =====================================================================
# PAGE CONFIGURATION
# =====================================================================

st.set_page_config(
    page_title="Network Dashboard (CORRECTED)",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main {background-color: #0f172a; color: #e2e8f0;}
    .stMetric {background-color: #1e293b; border-left: 4px solid #0ea5e9;}
    h1, h2, h3 {color: #f1f5f9;}
</style>
""", unsafe_allow_html=True)

st.title("🌐 Network Traffic Analysis Dashboard (CORRECTED)")
st.markdown("**RFC-Compliant Analysis** - Packet → Flow → Behavioral")

# =====================================================================
# SIDEBAR: FILE UPLOAD & CONFIGURATION
# =====================================================================

with st.sidebar:
    st.header("⚙️ Configuration")
    
    uploaded_file = st.file_uploader(
        "Upload PCAP file",
        type=["pcap", "pcapng"],
        help="Select a network capture file"
    )
    
    if uploaded_file is None:
        st.info("👉 Upload a PCAP file to begin analysis")
        st.stop()
    
    # Throughput window configuration
    throughput_window = st.slider(
        "Throughput Window (ms)",
        min_value=1000,
        max_value=10000,
        value=5000,
        step=1000,
        help="Time window for throughput calculation"
    )

# =====================================================================
# MAIN: LOAD AND PARSE PCAP
# =====================================================================

st.header("📂 Loading PCAP File...")

with st.spinner("Parsing packets..."):
    try:
        # Save uploaded file
        with open("temp_capture.pcap", "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Parse with progress
        parser = OptimizedPcapParser("temp_capture.pcap", chunk_size=50000)
        packets_df = parser.parse()
        
        if packets_df.empty:
            st.error("❌ No valid packets found in PCAP")
            st.stop()
        
        st.success(f"✅ Loaded {len(packets_df):,} packets")
        
    except Exception as e:
        st.error(f"❌ Error parsing PCAP: {e}")
        st.stop()

# =====================================================================
# STEP 1: RTT ANALYSIS
# =====================================================================

st.header("📊 Step 1: RTT Analysis")

with st.spinner("Calculating RTT..."):
    rtt_analyzer = RTTAnalyzer(packets_df)
    rtt_result = rtt_analyzer.analyze()
    
    if not rtt_result:
        st.warning("⚠️ No TCP handshakes found for RTT calculation")
        rtt_df = pd.DataFrame()
    else:
        rtt_df = rtt_result["dataframe"]
        rtt_stats = rtt_result["statistics"]
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(
                "Mean RTT",
                f"{rtt_stats['mean_rtt']:.2f}ms",
                delta=f"±{rtt_stats['std_rtt']:.2f}ms"
            )
        with col2:
            st.metric("Min RTT", f"{rtt_stats['min_rtt']:.2f}ms")
        with col3:
            st.metric("Max RTT", f"{rtt_stats['max_rtt']:.2f}ms")
        with col4:
            st.metric("Samples", rtt_stats['count'])

# =====================================================================
# STEP 2: JITTER ANALYSIS
# =====================================================================

st.header("📊 Step 2: Jitter Analysis")

with st.spinner("Calculating Jitter..."):
    jitter_analyzer = JitterAnalyzer(packets_df)
    jitter_result = jitter_analyzer.analyze()
    
    if not jitter_result:
        st.warning("⚠️ Insufficient data for jitter analysis")
        jitter_df = pd.DataFrame()
    else:
        jitter_df = jitter_result["dataframe"]
        jitter_stats = jitter_result["statistics"]
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(
                "Mean Jitter",
                f"{jitter_stats['mean_jitter_rfc3550_ms']:.2f}ms",
                help="RFC 3550 definition"
            )
        with col2:
            st.metric(
                "Median Jitter",
                f"{jitter_stats['median_jitter_rfc3550_ms']:.2f}ms"
            )
        with col3:
            st.metric(
                "Max Jitter",
                f"{jitter_stats['max_jitter_rfc3550_ms']:.2f}ms"
            )
        with col4:
            st.metric(
                "Flows Analyzed",
                jitter_stats["total_flows_analyzed"]
            )

# CORRECTED: Show RTT vs Jitter comparison
if not rtt_df.empty and not jitter_df.empty:
    st.subheader("RTT vs Jitter: Key Difference")
    
    comparison = compare_rtt_vs_jitter(rtt_df, jitter_df)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📏 RTT (Latency)")
        st.write(f"**Mean:** {comparison['rtt_metrics']['mean_ms']:.2f}ms")
        st.write(f"**Std Dev:** {comparison['rtt_metrics']['std_ms']:.2f}ms")
        st.write(f"**Range:** {comparison['rtt_metrics']['min_ms']:.2f} - {comparison['rtt_metrics']['max_ms']:.2f}ms")
        st.write(f"**Meaning:** {comparison['rtt_metrics']['explanation']}")
    
    with col2:
        st.markdown("### 🌊 Jitter (Variance)")
        st.write(f"**Mean:** {comparison['jitter_metrics']['mean_ms']:.2f}ms")
        st.write(f"**Std Dev:** {comparison['jitter_metrics']['std_ms']:.2f}ms")
        st.write(f"**Range:** {comparison['jitter_metrics']['min_ms']:.2f} - {comparison['jitter_metrics']['max_ms']:.2f}ms")
        st.write(f"**Meaning:** {comparison['jitter_metrics']['explanation']}")

# =====================================================================
# STEP 3: THROUGHPUT ANALYSIS
# =====================================================================

st.header("📊 Step 3: Throughput Stability Analysis")

with st.spinner("Analyzing throughput..."):
    tp_analyzer = ThroughputAnalyzer(packets_df)
    tp_result = tp_analyzer.analyze(time_window_ms=throughput_window)
    
    if not tp_result:
        st.warning("⚠️ Unable to analyze throughput")
    else:
        tp_stats = tp_result["statistics"]
        tp_stability = tp_result["stability_metric"]
        tp_anomalies = tp_result["anomalies"]
        
        # CORRECTED: Display stability and anomalies separately
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Mean Throughput",
                f"{tp_stats['mean_throughput_mbps']:.2f} Mbps"
            )
        with col2:
            st.metric(
                "Std Deviation",
                f"{tp_stats['std_dev_mbps']:.2f} Mbps"
            )
        with col3:
            st.metric(
                "Coefficient of Variation",
                f"{tp_stability['coefficient_of_variation_percent']:.2f}%"
            )
        with col4:
            st.metric(
                "Stability Score",
                f"{tp_stability['stability_score']}/100"
            )
        
        # CORRECTED: Classification (not marked unstable for normal variation)
        st.subheader(f"📈 Stability: {tp_stability['classification']}")
        st.write(tp_stability['interpretation'])
        
        # CORRECTED: Anomalies displayed separately
        if tp_anomalies['burst_count'] > 0:
            st.warning(
                f"⚠️ {tp_anomalies['burst_count']} abnormal burst(s) detected!"
            )
            
            # Show burst details
            with st.expander(f"Show {tp_anomalies['burst_count']} burst(s)"):
                for i, burst in enumerate(tp_anomalies['bursts'], 1):
                    st.write(f"**Burst {i}:**")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.write(f"Type: {burst['type']}")
                    with col2:
                        st.write(f"Severity: {burst['severity']}")
                    with col3:
                        st.write(f"Change: {burst['change_percent']:.1f}%")
                    st.write(f"Interpretation: {burst['interpretation']}")
                    st.divider()
        else:
            st.success("✓ No abnormal bursts detected")
        
        # Recommendation
        st.info(f"💡 {tp_analyzer.get_recommendation()}")

# =====================================================================
# STEP 4: TCP ANALYSIS
# =====================================================================

st.header("📊 Step 4: TCP Behavior Analysis")

with st.spinner("Analyzing TCP behavior..."):
    tcp_analyzer = TCPAnalyzer(packets_df)
    tcp_results = tcp_analyzer.get_all_tcp_analysis()
    
    # CORRECTED: Retransmission Bursts
    st.subheader("Retransmission Bursts (Fast Retransmit)")
    
    if tcp_results['retransmission']:
        retrans_df = tcp_results['retransmission']["dataframe"]
        retrans_stats = tcp_results['retransmission']["statistics"]
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(
                "Total Bursts",
                retrans_stats['total_bursts']
            )
        with col2:
            st.metric(
                "Mean Duplicates",
                f"{retrans_stats['mean_duplicates_per_burst']:.1f}",
                help="CORRECTED: Should be 3-5, not 15+"
            )
        with col3:
            st.metric(
                "High Severity",
                retrans_stats['high_severity_bursts']
            )
        
        st.write(f"**RFC 6582 Compliant:** {retrans_stats['rfc_6582_compliant']}")
        st.write(f"**Expected Range:** {retrans_stats['expected_range']}")
        
        # Show dataframe
        st.dataframe(retrans_df, use_container_width=True)
    else:
        st.info("✓ No retransmission bursts detected (Normal)")
    
    st.divider()
    
    # CORRECTED: Half-Open Connections
    st.subheader("Half-Open Connections")
    
    if tcp_results['half_open']:
        half_open_df = tcp_results['half_open']["dataframe"]
        half_open_stats = tcp_results['half_open']["statistics"]
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(
                "Total Half-Open",
                half_open_stats['total_half_open'],
                help="CORRECTED: Should be 0-2 in normal traffic, 50+ in attacks"
            )
        with col2:
            st.metric("Unique Flows", half_open_stats['unique_flows'])
        with col3:
            high_severity = half_open_stats['severity_distribution']['high']
            st.metric("High Severity", high_severity)
        
        st.write(f"**Expected in normal traffic:** 0-2")
        st.write(f"**Expected in port scan:** 50+")
        
        if half_open_stats['total_half_open'] > 10:
            st.warning(
                f"⚠️ {half_open_stats['total_half_open']} half-open connections detected!\n"
                "This suggests port scanning or network attacks."
            )
        
        # Show dataframe
        st.dataframe(half_open_df, use_container_width=True)
    else:
        st.success("✓ No half-open connections (Normal)")
    
    st.divider()
    
    # Slow Start
    st.subheader("TCP Slow Start Analysis")
    
    if tcp_results['slow_start']:
        slowstart_df = tcp_results['slow_start']["dataframe"]
        slowstart_stats = tcp_results['slow_start']["statistics"]
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Events Detected", slowstart_stats['total_events'])
        with col2:
            st.metric(
                "Mean Duration",
                f"{slowstart_stats['mean_duration']:.2f}ms"
            )
        with col3:
            st.metric(
                "Median Duration",
                f"{slowstart_stats['median_duration']:.2f}ms"
            )
        
        st.dataframe(slowstart_df, use_container_width=True)
    else:
        st.info("ℹ️ No clear slow start phases detected")

# =====================================================================
# STEP 5: FLOW MAPPING
# =====================================================================

st.header("📊 Step 5: Flow Mapping & Statistics")

with st.spinner("Mapping flows..."):
    # CORRECTED: Pass RTT data to FlowMapper
    flow_mapper = FlowMapper(packets_df, rtt_data=rtt_df)
    flow_result = flow_mapper.analyze()
    
    if not flow_result:
        st.warning("⚠️ Unable to create flow map")
    else:
        flow_map_df = flow_result["dataframe"]
        flow_stats = flow_result["statistics"]
        
        # Display statistics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Flows", flow_stats['total_flows'])
        with col2:
            st.metric("Internal", flow_stats['internal_flows'])
        with col3:
            st.metric("External", flow_stats['external_flows'])
        with col4:
            st.metric(
                "Total Data",
                f"{flow_stats['total_bytes'] / (1024**3):.2f} GB"
            )
        
        st.divider()
        
        # CORRECTED: Latency metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric(
                "Avg Latency",
                f"{flow_stats['avg_latency_ms']:.2f} ms",
                help="CORRECTED: True RTT, not flow duration"
            )
        with col2:
            st.metric("Max Latency", f"{flow_stats['max_latency_ms']:.2f} ms")
        with col3:
            st.metric("Min Latency", f"{flow_stats['min_latency_ms']:.2f} ms")
        with col4:
            st.metric(
                "Flows w/ RTT",
                f"{flow_stats['flows_with_rtt']}/{flow_stats['total_flows']}"
            )
        
        st.divider()
        
        # Show flow map table
        st.subheader("Flow Map Table")
        
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            traffic_filter = st.multiselect(
                "Traffic Type",
                ["Within College", "Outside College"],
                default=["Within College", "Outside College"]
            )
        with col2:
            protocol_filter = st.multiselect(
                "Protocol",
                flow_map_df["protocol"].unique(),
                default=flow_map_df["protocol"].unique()
            )
        
        # Apply filters
        filtered_df = flow_map_df[
            (flow_map_df["traffic_type"].isin(traffic_filter)) &
            (flow_map_df["protocol"].isin(protocol_filter))
        ]
        
        # Display
        st.dataframe(
            filtered_df,
            use_container_width=True,
            height=400
        )
        
        # Export button
        csv = filtered_df.to_csv(index=False)
        st.download_button(
            label="📥 Download Flow Data (CSV)",
            data=csv,
            file_name="flow_analysis.csv",
            mime="text/csv"
        )

# =====================================================================
# SUMMARY & RECOMMENDATIONS
# =====================================================================

st.header("📋 Analysis Summary")

summary_cols = st.columns(4)

with summary_cols[0]:
    st.metric("Packets", f"{len(packets_df):,}")

with summary_cols[1]:
    st.metric("TCP Flows", len(packets_df[packets_df["protocol"]=="TCP"].drop_duplicates(subset=["src_ip", "dst_ip", "src_port", "dst_port"])))

with summary_cols[2]:
    st.metric("Abnormalities", sum([
        0 if not tp_result else tp_anomalies['burst_count'],
        0 if not tcp_results['retransmission'] else tcp_results['retransmission']['statistics']['total_bursts'],
        0 if not tcp_results['half_open'] else tcp_results['half_open']['statistics']['total_half_open']
    ]))

with summary_cols[3]:
    status = "✅ Healthy" if sum([
        0 if not tp_result else tp_anomalies['burst_count'],
        0 if not tcp_results['retransmission'] else tcp_results['retransmission']['statistics']['total_bursts'],
        0 if not tcp_results['half_open'] else tcp_results['half_open']['statistics']['total_half_open']
    ]) < 5 else "⚠️ Issues Detected"
    st.metric("Network Status", status)

# Final recommendation
st.divider()
st.subheader("🎯 Recommendations")

recommendations = []

if tp_stability['coefficient_of_variation_percent'] > 60:
    recommendations.append("• High throughput variation - Check for congestion")

if not rtt_df.empty and rtt_stats['mean_rtt'] > 150:
    recommendations.append("• High RTT detected - Verify network path")

if tcp_results['retransmission'] and tcp_results['retransmission']['statistics']['total_bursts'] > 5:
    recommendations.append("• Multiple retransmission events - Investigate packet loss")

if tcp_results['half_open'] and tcp_results['half_open']['statistics']['total_half_open'] > 5:
    recommendations.append("• Multiple half-open connections - Possible attack or network issue")

if not recommendations:
    st.success("✅ Network traffic appears normal. No immediate action required.")
else:
    for rec in recommendations:
        st.warning(rec)

# Footer
st.divider()
st.markdown("""
---
**Dashboard Version:** 2.0 (CORRECTED)  
**Compliance:** RFC 6582 (TCP Congestion Control), RFC 3550 (Jitter)  
**Last Updated:** 2024
""")
```

---

## 🔧 KEY INTEGRATION POINTS

### 1. RTT Data → FlowMapper

**BEFORE (WRONG):**
```python
flow_mapper = FlowMapper(packets_df)  # No RTT data
# Result: latency_ms = flow_duration (10000ms)
```

**AFTER (CORRECT):**
```python
rtt_analyzer = RTTAnalyzer(packets_df)
rtt_result = rtt_analyzer.analyze()
rtt_df = rtt_result["dataframe"]

flow_mapper = FlowMapper(packets_df, rtt_data=rtt_df)  # Pass RTT
# Result: latency_ms = actual RTT (50ms)
```

---

### 2. Throughput: Separate Stability from Anomalies

**BEFORE:**
```python
if cv > 60:
    st.warning("Unstable throughput")  # Wrong!
```

**AFTER:**
```python
stability = tp_result["stability_metric"]
anomalies = tp_result["anomalies"]

# Display stability
st.write(stability["classification"])  # "Stable" for fiber

# Display anomalies separately
if anomalies["burst_count"] > 0:
    st.warning(f"⚠️ {anomalies['burst_count']} abnormal burst(s)")
```

---

### 3. Duplicate ACK Display

**BEFORE:**
```python
st.metric("Duplicate Count", 15)  # This is wrong
```

**AFTER:**
```python
dup_counts = retrans_df["duplicate_count"].values

# Verify they're reasonable
assert all(3 <= count <= 5 for count in dup_counts), "Invalid counts!"

st.metric(
    "Mean Duplicates",
    f"{dup_counts.mean():.1f}",
    help="CORRECTED: Should be 3-5, not 15+"
)
```

---

### 4. RTT vs Jitter Display

**BEFORE:**
```python
# Jitter calculated from RTT differences (WRONG)
st.write(f"RTT: {rtt_mean}ms")
st.write(f"Jitter: {jitter_mean}ms")
# They look similar - that's the problem!
```

**AFTER:**
```python
# Use comparison function
comparison = compare_rtt_vs_jitter(rtt_df, jitter_df)

col1, col2 = st.columns(2)
with col1:
    st.write(f"RTT (Latency): {comparison['rtt_metrics']['mean_ms']:.2f}ms")
with col2:
    st.write(f"Jitter (Variance): {comparison['jitter_metrics']['mean_ms']:.2f}ms")
# Now they're clearly different!
```

---

### 5. Half-Open Detection

**BEFORE:**
```python
st.metric("Half-Open", 15)  # Expected 0-2, this is wrong!
```

**AFTER:**
```python
half_open_count = half_open_stats['total_half_open']

if half_open_count == 0:
    st.success("✓ No half-open connections (Normal)")
elif half_open_count < 5:
    st.info(f"ℹ️ {half_open_count} half-open (Investigate)")
else:
    st.warning(
        f"⚠️ {half_open_count} half-open detected!\n"
        "Suggests port scanning or network attacks"
    )
```

---

## ✅ DEPLOYMENT CHECKLIST

- [ ] Replace all module files with CORRECTED versions
- [ ] Update app.py to use new integration pattern
- [ ] Pass RTT data to FlowMapper
- [ ] Verify duplicate ACK counts are 3-5
- [ ] Separate stability from anomalies in throughput
- [ ] Display RTT and Jitter as different metrics
- [ ] Test with real PCAP file
- [ ] Verify output values are in expected ranges
- [ ] Check logs for any errors
- [ ] Deploy to production

---

**Integration complete and ready for testing!** ✅
