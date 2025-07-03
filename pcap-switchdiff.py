#troubleshooting tool that reads 2 pcap files and check if packets were dropped and how much latency the networking device introduced processing thes packets 

from scapy.all import rdpcap, IP, UDP, TCP
from datetime import datetime, timezone
import sys

BUFFER_SEC = 0.02

def print_top_latencies(latencies, dir_label, top_n=10):
    if not latencies:
        print(f"\nTop {top_n} highest latency {dir_label}: None")
        return
    print(f"\nTop {top_n} highest latency {dir_label}:")
    for pA, pB, lat in sorted(latencies, key=lambda x: -x[2])[:top_n]:
        print(f"  {format_time(pA[0])} (#{pA[2]}) → {format_time(pB[0])} (#{pB[2]}) "
              f"latency: {lat*1000:.3f} ms")
    avg_lat = sum(l[2] for l in latencies) / len(latencies)
    print(f"Average latency {dir_label}: {avg_lat*1000:.3f} ms")

def print_high_latency_packets(latencies, dir_label, threshold_ratio=1000):
    if not latencies:
        print(f"\nNo {dir_label} packets to analyze for high latency.")
        return
    avg_lat = sum(l[2] for l in latencies) / len(latencies)
    threshold = avg_lat * threshold_ratio
    print(f"\nPackets with latency > {threshold_ratio*100:.0f}% of average ({threshold*1000:.3f} ms) for {dir_label}:")
    count = 0
    for pA, pB, lat in latencies:
        if lat > threshold:
            print(f"  {format_time(pA[0])} (#{pA[2]}) → {format_time(pB[0])} (#{pB[2]}) "
                  f"latency: {lat*1000:.3f} ms")
            count += 1
    if count == 0:
        print("  None above threshold.")

def format_time(ts):
    ts_float = float(ts)
    dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"

def extract_flows(filename, port_label):
    # port_label: string for debugging, eg. "3" or "4"
    packets = rdpcap(filename)
    flow_dict = {}  # Key: (proto, src, sport, dst, dport, payload) Value: [timestamp, frame_num, port_label]
    time_list = []
    pkt_info = []
    for idx, pkt in enumerate(packets):
        if IP in pkt:
            ip = pkt[IP]
            l4_proto = None
            l4_layer = None
            if UDP in pkt:
                l4_proto = "UDP"
                l4_layer = pkt[UDP]
            elif TCP in pkt:
                l4_proto = "TCP"
                l4_layer = pkt[TCP]
            else:
                continue
            key = (l4_proto, ip.src, l4_layer.sport, ip.dst, l4_layer.dport, bytes(l4_layer.payload))
            pkt_info.append( (float(pkt.time), key, idx+1, port_label) )
            time_list.append(float(pkt.time))
    return pkt_info, time_list

def print_time_range(label, t_start, t_end):
    dur = t_end - t_start
    print(f"{label}: {format_time(t_start)} ({t_start:.6f}) - {format_time(t_end)} ({t_end:.6f}) (duration: {dur:.3f} s)")

def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} port3.pcap port4.pcap port3_label port4_label")
        print("  Example: python pdiff_bidir.py port3.pcap port4.pcap 3 4")
        sys.exit(1)

    pcap3, pcap4, label3, label4 = sys.argv[1:5]
    pkts3, times3 = extract_flows(pcap3, label3)
    pkts4, times4 = extract_flows(pcap4, label4)
    print(f"Read {len(pkts3)} packets from port {label3}, {len(pkts4)} from port {label4}.")

    # Overlap window
    min3, max3 = min(times3), max(times3)
    min4, max4 = min(times4), max(times4)
    overlap_start = max(min3, min4) + BUFFER_SEC
    overlap_end   = min(max3, max4) - BUFFER_SEC
    print()
    print_time_range(f"Port {label3} capture", min3, max3)
    print_time_range(f"Port {label4} capture", min4, max4)
    print()
    print_time_range("Overlapping time window", overlap_start, overlap_end)

    # Only analyze packets in overlap
    pkts3_overlap = [p for p in pkts3 if overlap_start <= p[0] <= overlap_end]
    pkts4_overlap = [p for p in pkts4 if overlap_start <= p[0] <= overlap_end]
    print(f"Packets in overlapping window: port{label3}={len(pkts3_overlap)}, port{label4}={len(pkts4_overlap)}")

    # Build lookups for quick matching
    from collections import defaultdict, deque
    lookup4 = defaultdict(deque)
    for p in pkts4_overlap:
        lookup4[p[1]].append(p)
    lookup3 = defaultdict(deque)
    for p in pkts3_overlap:
        lookup3[p[1]].append(p)

    # Analyze 3 -> 4 direction: match each 3 to earliest 4, compute latency, mark used
    used4 = set()
    latencies_3to4 = []
    dropped_3to4 = []
    for p3 in pkts3_overlap:
        k = p3[1]
        # Try to find in port4, use only once
        while lookup4[k]:
            p4 = lookup4[k].popleft()
            if (p4[2], p4[3]) not in used4:
                used4.add((p4[2], p4[3]))
                latency = float(p4[0]) - float(p3[0])
                latencies_3to4.append( (p3, p4, latency) )
                break
        else:
            dropped_3to4.append(p3)

    # Analyze 4 -> 3 direction: match each 4 to earliest 3, compute latency, mark used
    used3 = set()
    latencies_4to3 = []
    dropped_4to3 = []
    for p4 in pkts4_overlap:
        k = p4[1]
        while lookup3[k]:
            p3 = lookup3[k].popleft()
            if (p3[2], p3[3]) not in used3:
                used3.add((p3[2], p3[3]))
                latency = float(p3[0]) - float(p4[0])
                latencies_4to3.append( (p4, p3, latency) )
                break
        else:
            dropped_4to3.append(p4)

    # Print summary/results
    print(f"\nPort {label3} → {label4}:")
    print(f"  Matched: {len(latencies_3to4)}  Dropped: {len(dropped_3to4)}")
    if latencies_3to4:
        lat_ms = [l[2]*1000 for l in latencies_3to4 if l[2] >= 0]
        print(f"  Processing latency (ms): min={min(lat_ms):.3f} max={max(lat_ms):.3f} avg={sum(lat_ms)/len(lat_ms):.3f}")

    print(f"\nPort {label4} → {label3}:")
    print(f"  Matched: {len(latencies_4to3)}  Dropped: {len(dropped_4to3)}")
    if latencies_4to3:
        lat_ms = [l[2]*1000 for l in latencies_4to3 if l[2] >= 0]
        print(f"  Processing latency (ms): min={min(lat_ms):.3f} max={max(lat_ms):.3f} avg={sum(lat_ms)/len(lat_ms):.3f}")

    # Optionally: print first N drops and largest latency packets for inspection
    print(f"\nFirst 5 dropped port {label3} → {label4}:")
    for p in dropped_3to4[:5]:
        print(f"  Frame #{p[2]} {format_time(p[0])} {p[1]}")

    print(f"\nFirst 5 dropped port {label4} → {label3}:")
    for p in dropped_4to3[:5]:
        print(f"  Frame #{p[2]} {format_time(p[0])} {p[1]}")

    # Optionally: print highest latency packets for each direction

    print_top_latencies(latencies_3to4, f"port {label3} → {label4}")
    #print_high_latency_packets(latencies_3to4, f"port {label3} → {label4}")

    print_top_latencies(latencies_4to3, f"port {label4} → {label3}")
    #fprint_high_latency_packets(latencies_4to3, f"port {label4} → {label3}")

if __name__ == "__main__":
    main()
