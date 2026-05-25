# Network Traffic Behavior & Causality Dashboard

A Streamlit-based dashboard for analyzing **5-minute captured traffic** and **live network traffic** to visualize network behavior, detect anomalies, and understand traffic causality in real time.

## Features

### RTT (Round Trip Time)
- Visualizes RTT trends over time
- Color-coded latency zones:
  - 🔴 High RTT
  - 🟠 Medium RTT
  - 🟢 Normal RTT
- Detects latency spikes and network delays

### Jitter Analysis
- Displays **Time vs Jitter** graph
- Measures packet delay variation
- Helps identify unstable network performance

### Packet Reordering Frequency
- Detects out-of-order packet arrivals
- Calculates packet reordering frequency
- Useful for diagnosing routing or congestion issues

### TCP Slow Start Duration
- Identifies TCP slow start behavior
- Estimates connection ramp-up duration
- Helps analyze TCP performance efficiency

### Retransmission Burst Detection
- Detects abnormal retransmission bursts
- Highlights possible packet loss or duplicate ACK events
- Differentiates normal retransmissions from burst anomalies

### Half-Open Connection Detection
- Detects incomplete TCP three-way handshakes
- Identifies missing ACK scenarios
- Helps diagnose connection failures and abnormal traffic

### Throughput Stability Analysis
- Displays **Time vs Throughput** graph
- Monitors throughput consistency over time
- Detects actual abnormal throughput bursts
- Avoids false instability alerts caused by small throughput variations

### Flow Map Table
Displays:
- Source/Destination pair
- Protocol type
- Latency information
- Traffic classification:
  - Internal network traffic
  - External network traffic

## Supported Modes

### 1. Captured Traffic Analysis
- Analyze previously captured `.pcap` / `.pcapng` files
- Generates detailed network behavior insights

### 2. Live Traffic Capture
- Captures and analyzes real-time network traffic
- Dynamically updates visualizations and metrics
- Can export captured traffic data for further analysis

## Objective

The dashboard is designed to visualize the **behavior and causality of network traffic** by combining traffic metrics, anomaly detection, and real-time insights from both captured datasets and live traffic.

## Tech Stack
- Python
- Streamlit
- Scapy
- Pandas
- Matplotlib / Plotly

## Input Requirements
- Captured traffic: `.pcap` or `.pcapng`
- Live mode: active network traffic for real-time analysis

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- Administrator privileges (for live packet capture)

**1. Install dependencies:**
```bash
pip install -r requirements.txt
```

**2. Run the dashboard:**
```bash
streamlit run app.py
```

**3. Open in browser:**
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
│   └── network_traffic_captured.pcap  # Your captured traffic file
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
2. **Sidebar**: Select " Live Capture"
3. **Configure**:
   - Set "Time window (seconds)" (10-300 seconds)
4. **Start**: Click "Start Live Capture" button
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
- Ensure file is valid `.pcap` or `.pcapng` format
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
1. TCP packets are grouped into flows
2. Request–response packet pairs are identified using TCP sequence and acknowledgment relationships
3. RTT is calculated as the time difference between matched packet events
4. High RTT thresholds are dynamically used to classify latency zones:
   - 🔴 High RTT
   - 🟠 Medium RTT
   - 🟢 Normal RTT
5. RTT spikes are highlighted to indicate potential congestion or delays

### **How Jitter is Calculated**
1. Consecutive packet arrival times are analyzed within a flow
2. Inter-arrival delay differences are computed
3. Jitter is measured as the variation between consecutive packet delays
4. Displayed as a **Time vs Jitter** graph to observe delay instability

### **How Packet Reordering is Detected**
1. TCP sequence numbers are examined flow-wise
2. A packet is considered reordered if a lower sequence number appears after a higher one
3. Reordering frequency is calculated per flow
4. Higher reordering may indicate routing inconsistencies or congestion

### **How TCP Slow Start is Identified**
1. TCP connection initiation is identified through SYN packets
2. Early-stage packet transmission behavior is analyzed
3. The period of increasing transmission activity is treated as slow start
4. Slow start duration is estimated for TCP flow performance analysis

### **How Retransmission Bursts are Detected**
1. TCP retransmissions are tracked within each flow
2. Duplicate ACK patterns and repeated transmissions are analyzed
3. Only **actual abnormal retransmission bursts** are flagged
4. Isolated or normal retransmissions are not treated as burst anomalies
5. Burst severity is determined based on retransmission concentration within short time intervals

### **How Half-Open Connections are Detected**
1. TCP three-way handshakes are monitored
2. SYN and SYN-ACK packets are tracked
3. Connections missing the final ACK are classified as **half-open**
4. Used to identify failed or incomplete connection attempts

### **How Throughput Stability is Calculated**
1. Throughput is measured over time during traffic capture
2. A **Time vs Throughput** graph is generated
3. Stability is evaluated using an acceptable throughput threshold range
4. Small throughput fluctuations are treated as normal
5. Only significant abnormal throughput bursts are flagged
6. Low but steady throughput is considered **stable**, avoiding false instability detection

### **How Flows are Classified**
1. Source and destination IP addresses are analyzed
2. Traffic is classified as:
   - **Internal traffic** → local/private network communication
   - **External traffic** → communication outside the local network
3. Flow map includes:
   - Source/Destination pair
   - Protocol
   - Latency
   - Traffic classification

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
