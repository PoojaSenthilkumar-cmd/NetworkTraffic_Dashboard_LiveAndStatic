# 🌐 Network Traffic Analysis Dashboard

A comprehensive Streamlit-based dashboard for visualizing and analyzing network traffic behavior from both captured PCAP files and live network data.

## 📊 Dashboard Features

The dashboard provides real-time analysis of 8 key network metrics:

### 1. **RTT (Round Trip Time) Analysis** 
   - **What it is**: Latency between request and response
   - **Color Zones**:
     - 🟢 Green: Low RTT < 50ms (Excellent)
     - 🟠 Orange: Medium RTT 50-100ms (Good)
     - 🔴 Red: High RTT > 100ms (Poor/Congestion)
   - **Why it matters**: Indicates network quality and congestion

### 2. **Jitter Analysis**
   - **What it is**: Variation in packet delay over time
   - **Why it matters**: High jitter causes voice/video quality issues
   - **Visualization**: Time vs Jitter graph

### 3. **Packet Reordering Detection**
   - **What it is**: Packets arriving out-of-sequence
   - **Why it matters**: Indicates routing issues or network congestion
   - **Frequency**: Shows how often reordering occurs

### 4. **TCP Slow Start Duration**
   - **What it is**: Time for TCP connection to ramp up to full speed
   - **Why it matters**: Indicates initial connection quality
   - **Identification**: Tracks connection initialization phase

### 5. **Retransmission Bursts** (Duplicate ACKs)
   - **What it is**: Multiple retransmissions of same data
   - **Why it matters**: Sign of network congestion/packet loss
   - **Severity Levels**: Medium (3-5 duplicates) / High (5+ duplicates)

### 6. **Half-Open Connections**
   - **What it is**: TCP handshake missing final ACK
   - **Why it matters**: Indicates connection establishment failures
   - **Detection**: Monitors 3-way handshake completion

### 7. **Throughput Stability**
   - **What it is**: Data transfer rate over time
   - **Stability Score**: 0-100% (higher = more stable)
   - **Why it matters**: Shows network consistency

### 8. **Flow Map Table**
   - **Contents**: Source/Destination pairs with:
     - Protocol (TCP/UDP/ICMP)
     - Latency per flow
     - Traffic classification (Internal/External)
     - Identified service
     - Data transferred

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- Administrator privileges (for live packet capture)

### Installation

**1. Navigate to project directory:**
```bash
cd TASK4_STREAMLITDASHBOARD
```

**2. Create virtual environment:**

*On Windows:*
```bash
python -m venv venv
venv\Scripts\activate
```

*On macOS/Linux:*
```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies:**
```bash
pip install -r requirements.txt
```

**4. Run the dashboard:**
```bash
streamlit run app.py
```

**5. Open in browser:**
- Automatically opens at `http://localhost:8501`
- If not, manually navigate to that URL

---

## 📁 Project Structure

```
TASK4_STREAMLITDASHBOARD/
│
├── analyzer/                    # Analysis modules
│   ├── parser.py               # Reads PCAP files
│   ├── rtt.py                  # RTT analysis
│   ├── jitter.py               # Jitter calculation
│   ├── reordering.py           # Out-of-order detection
│   ├── tcp_analysis.py         # TCP behavior (slow start, retrans, half-open)
│   ├── throughput.py           # Throughput measurement
│   └── flowmap.py              # Flow mapping & traffic classification
│
├── liveCaptureData/
│   └── live_capture.py         # Real-time packet capture
│
├── capturedData/
│   └── network_traffic_capture_5min.pcap  # Your captured traffic file
│
├── app.py                      # Main Streamlit dashboard (MAIN FILE)
├── requirements.txt            # Python dependencies
├── README.md                   # This file
└── output/                     # (Create this) For export data

```

---

## 💻 How to Use the Dashboard

### **Option 1: Analyze PCAP File**

1. **Launch the app** (see "Run the dashboard" above)
2. **Sidebar**: Select "📁 Upload PCAP File"
3. **Upload**: Click file uploader and select your `.pcap` file
4. **Wait**: Dashboard analyzes in real-time (~10-30 seconds depending on file size)
5. **Explore**: Navigate tabs to see different analyses:
   - **RTT & Jitter Tab**: Time series graphs with color zones
   - **TCP Analysis Tab**: Slow start, retransmissions, half-open connections
   - **Throughput & Flow Map Tab**: Stability metrics and detailed flow table
   - **Statistics Tab**: Summary metrics
   - **Export Tab**: Download results as CSV

### **Option 2: Capture Live Traffic**

1. **Launch the app**
2. **Sidebar**: Select "📡 Live Capture"
3. **Configure**:
   - Set "Capture Duration" (10-300 seconds)
   - Set "Packet Limit" (10-10,000 packets)
4. **Start**: Click "🔴 Start Live Capture" button
5. **Monitor**: Progress bar shows capture progress
6. **Analyze**: Same tabs available as PCAP analysis

---

## 📊 Understanding the Visualizations

### **RTT Time Series Graph**
- **X-axis**: Time
- **Y-axis**: RTT in milliseconds
- **Green line**: Your RTT values
- **Dash lines**: Thresholds (50ms, 100ms)
- **Interpretation**: 
  - Flat lines = stable network
  - Spikes = congestion events

### **Jitter Graph**
- **X-axis**: Time
- **Y-axis**: Jitter (ms)
- **Shaded area**: Visual emphasis
- **Interpretation**:
  - Low values = smooth experience
  - High values = quality issues

### **Packet Reordering Bar Chart**
- **Each bar**: Number of reordering events in that time period
- **Red color**: Indicates problems
- **Interpretation**: Should be mostly zero (good network)

### **TCP Slow Start Scatter**
- **Each point**: One slow start event
- **Color intensity**: Initial window size
- **Y-axis**: Duration (ms)
- **Interpretation**: Larger durations = slower connections

### **Retransmission Bursts**
- **Bar height**: Number of duplicate ACKs
- **Red bars**: High severity (5+ duplicates)
- **Orange bars**: Medium severity
- **Interpretation**: More bars = more congestion

### **Throughput Graph**
- **X-axis**: Time
- **Y-axis**: Megabits per second (Mbps)
- **Shaded area**: Visual emphasis
- **Interpretation**: 
  - Flat line = stable connection
  - Sawtooth pattern = variable network

### **Flow Map Table**
Columns explained:
- **src_ip/dst_ip**: Who's talking to whom
- **protocol**: Communication type (TCP/UDP/ICMP)
- **packet_count**: How many packets in this conversation
- **total_bytes**: Amount of data transferred
- **latency_ms**: Response time for this flow
- **throughput_mbps**: Data transfer rate for this flow
- **traffic_type**: "Internal" = college network, "External" = outside
- **service**: Detected service (HTTP, DNS, SSH, etc.)

---

## 🔧 Configuration & Customization

### **Modify College Network Ranges**

In `analyzer/flowmap.py`, find this section:

```python
COLLEGE_NETWORKS = [
    '192.168.0.0/16',      # Change these to your college's IP ranges
    '10.0.0.0/8',
    '172.16.0.0/12',
    '202.130.0.0/16',
]
```

Replace with your actual college network CIDR ranges.

### **Change Analysis Time Windows**

In `app.py`, find the throughput analysis call:

```python
results['throughput'] = throughput_analyzer.analyze(time_window_ms=1000)  # Change 1000 to desired ms
```

### **Adjust Color Thresholds**

In `analyzer/rtt.py`, modify the `_get_color_zones()` method:

```python
return {
    'green': {'range': (0, 50), ...},      # Change 50 to desired threshold
    'orange': {'range': (50, 100), ...},   # Change these ranges
    'red': {'range': (100, float('inf')), ...},
}
```

---

## 📝 Output Files

When you export data (in "Export Data" tab), files are saved as:

- `rtt_YYYYMMDD_HHMMSS.csv` - RTT measurements
- `jitter_YYYYMMDD_HHMMSS.csv` - Jitter data
- `reordering_YYYYMMDD_HHMMSS.csv` - Reordering events
- `throughput_YYYYMMDD_HHMMSS.csv` - Throughput measurements
- `flowmap_YYYYMMDD_HHMMSS.csv` - Flow table

Each CSV includes:
- **timestamp**: When measurement occurred
- **value**: The metric value
- **src_ip/dst_ip**: Source and destination
- **Additional fields**: Protocol, port, flow info, etc.

---

## 🐛 Troubleshooting

### **Issue: "No packets captured" with Live Capture**
**Solution**: 
- Ensure network traffic is active (open a website, download something)
- May need administrator/root privileges
- Try increasing capture duration
- Check network interface is active

### **Issue: "Failed to parse PCAP file"**
**Solution**:
- Ensure file is valid `.pcap` format (not `.pcapng`)
- File must contain network packets
- Try with different PCAP file

### **Issue: "ModuleNotFoundError"**
**Solution**:
- Ensure virtual environment is activated
- Re-run: `pip install -r requirements.txt`
- Verify Python 3.8+ is installed

### **Issue: Streamlit runs but shows blank page**
**Solution**:
- Wait for initial analysis to complete (check terminal)
- Refresh browser
- Check browser console for errors (F12)

### **Issue: "Permission denied" on Linux/Mac**
**Solution**:
- Run with sudo: `sudo streamlit run app.py`
- May need sudo for packet capture with scapy

---

## 📚 Technical Details

### **How RTT is Calculated**
1. Find pairs of outgoing request packets (SYN or data) and incoming acknowledgments
2. Match them using sequence/acknowledgment numbers
3. Calculate time difference between pair
4. Filter outliers (< 10,000 ms)

### **How Jitter is Calculated**
1. For each flow, calculate inter-arrival times between consecutive packets
2. Jitter = variation in these inter-arrival times
3. Calculated as absolute difference between consecutive delays

### **How Reordering is Detected**
1. Examine sequence numbers in TCP packets
2. When seq_num[i] > seq_num[i+1], packet is out of order
3. Count such occurrences per flow

### **How TCP Slow Start is Identified**
1. Find SYN packet (start of connection)
2. Look for data packets following SYN-ACK
3. Track until packet sizes stabilize
4. Duration = time from SYN to stabilization

### **How Retransmission Bursts are Detected**
1. Track ACK numbers in flow
2. When same ACK appears 3+ times within 1 second = duplicate ACK
3. 5+ duplicates = high severity

### **How Flows are Classified**
1. Check source/destination IP ranges
2. Private ranges (10.x, 172.16-31.x, 192.168.x) = Internal
3. Otherwise = External

---

## 🎯 Interpretation Guide

### **Network Health Scorecard**

| Metric | Excellent | Good | Fair | Poor |
|--------|-----------|------|------|------|
| RTT | <20ms | 20-50ms | 50-100ms | >100ms |
| Jitter | <5ms | 5-20ms | 20-50ms | >50ms |
| Reordering | None | <1% | 1-5% | >5% |
| Throughput Stability | >90% | 70-90% | 50-70% | <50% |
| Half-Open Connections | 0 | 0 | <5% | >5% |

---

## 📊 Real-World Examples

### **Example 1: Detecting Congestion**
- ✅ **Signs**: Increasing RTT, multiple retransmission bursts, packet reordering spikes
- ✅ **Action**: Check network load, prioritize critical traffic

### **Example 2: Poor Streaming Quality**
- ✅ **Signs**: High jitter (>50ms), unstable throughput, variable RTT
- ✅ **Action**: Reduce streaming quality, check interference

### **Example 3: Connection Problems**
- ✅ **Signs**: Many half-open connections, slow TCP slow start, frequent timeouts
- ✅ **Action**: Check firewall rules, network stability

---

## 🔗 Next Steps

1. **Customize** network ranges in `flowmap.py` for your college
2. **Create output folder**: `mkdir output`
3. **Start analyzing**: Upload PCAP or capture live traffic
4. **Export results**: Save CSVs for reporting
5. **Monitor continuously**: Use live capture for real-time monitoring

---

## 📄 License

Educational project for network analysis and visualization.

---
