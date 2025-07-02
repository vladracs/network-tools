# compare 2 pcap files to find packets dropped inside a switch ( only L2 changes expected)


from scapy.all import rdpcap, IP, UDP, TCP
import sys
from datetime import datetime, timezone

BUFFER_SEC = 0.01  # 10 milliseconds buffer for time window (adjust as needed)

def format_time(ts):
    # Ensure ts is a float, and use timezone-aware UTC datetime
    ts_float = float(ts)
    dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"

def summary(pkt):
    ts, src_ip, dst_ip, sport, dport, proto, payload, frame_number = pkt
    return (f"Packet #{frame_number}: {format_time(ts)} ({ts:.6f}) "
            f"{src_ip}:{sport} -> {dst_ip}:{dport} {proto}, "
            f"PayloadLen={len(payload)}, Payload[0:16]={payload[:16].hex()}")

def extract_l4_keys_with_ts(filename, filter_ip=None):
    packets = rdpcap(filename)
    pkt_keys = []
    ts_list = []
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
                continue  # Not UDP or TCP

            if filter_ip is not None:
                if ip.src != filter_ip and ip.dst != filter_ip:
                    continue

            pkt_keys.append( (
                pkt.time,
                ip.src,
                ip.dst,
                l4_layer.sport,
                l4_layer.dport,
                l4_proto,
                bytes(l4_layer.payload),
                idx+1  # Packet/frame number (Wireshark numbering)
            ))
            ts_list.append(pkt.time)
    return pkt_keys, ts_list

def print_time_range(label, t_start, t_end):
    dur = t_end - t_start
    print(f"{label}: {format_time(t_start)} ({t_start:.6f}) - {format_time(t_end)} ({t_end:.6f}) (duration: {dur:.3f} s)")

def main():
    if len(sys.argv) not in [3, 4]:
        print(f"Usage: {sys.argv[0]} ingress.pcap egress.pcap [client_ip]")
        print("  Optionally filter only packets with this client IP.")
        sys.exit(1)
    ingress_file = sys.argv[1]
    egress_file  = sys.argv[2]
    filter_ip = sys.argv[3] if len(sys.argv) == 4 else None

    print(f"Reading INGRESS from {ingress_file}")
    ingress, ingress_ts = extract_l4_keys_with_ts(ingress_file, filter_ip=filter_ip)
    print(f"Total UDP/TCP packets in ingress: {len(ingress)}")

    print(f"Reading EGRESS from {egress_file}")
    egress, egress_ts = extract_l4_keys_with_ts(egress_file, filter_ip=filter_ip)
    print(f"Total UDP/TCP packets in egress: {len(egress)}")

    # Calculate capture durations
    ingress_min, ingress_max = min(ingress_ts), max(ingress_ts)
    egress_min, egress_max   = min(egress_ts), max(egress_ts)
    print()
    print_time_range("Ingress capture", ingress_min, ingress_max)
    print_time_range("Egress  capture", egress_min, egress_max)

    # Find the overlap window
    overlap_start = max(ingress_min, egress_min) + BUFFER_SEC
    overlap_end   = min(ingress_max, egress_max) - BUFFER_SEC
    if overlap_end < overlap_start:
        overlap_end = overlap_start  # Avoid negative window
    overlap_dur   = max(0, overlap_end - overlap_start)
    print()
    print_time_range("Overlapping time window", overlap_start, overlap_end)

    # Filter to overlapping window
    ingress_overlap = [pkt for pkt in ingress if overlap_start <= pkt[0] <= overlap_end]
    egress_overlap  = [pkt for pkt in egress  if overlap_start <= pkt[0] <= overlap_end]

    print(f"Packets in overlapping window: ingress={len(ingress_overlap)}, egress={len(egress_overlap)}")

    # Remove timestamps and frame number for matching
    ingress_nots = [pkt[1:-1] for pkt in ingress_overlap]
    egress_nots  = [pkt[1:-1] for pkt in egress_overlap]

    # Egress working list to avoid double-matching
    egress_working = egress_nots.copy()
    dropped = []

    for i, pkt_in in enumerate(ingress_nots):
        found = False
        for j, pkt_out in enumerate(egress_working):
            if pkt_in == pkt_out:
                del egress_working[j]
                found = True
                break
        if not found:
            dropped.append(ingress_overlap[i])  # Keep full info for reporting

    print(f"\nDropped packets (in ingress overlap, not found in egress overlap): {len(dropped)}")
    for pkt in dropped:
        print("  " + summary(pkt))

    if not dropped:
        print("\nAll ingress packets in overlap window were found in egress!")

if __name__ == "__main__":
    main()
