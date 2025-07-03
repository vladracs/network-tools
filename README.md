# network-tools

<pre> ```PDIFF-PROC example
pdiff-proc.py voice3a_strip.pcap voice4a_strip.pcap 3 4
Read 765 packets from port 3, 765 from port 4.

Port 3 capture: 2025-07-02 11:18:14.811 UTC (1751455094.811714) - 2025-07-02 11:18:22.340 UTC (1751455102.340306) (duration: 7.529 s)
Port 4 capture: 2025-07-02 11:18:14.811 UTC (1751455094.811768) - 2025-07-02 11:18:22.340 UTC (1751455102.340251) (duration: 7.528 s)

Overlapping time window: 2025-07-02 11:18:14.831 UTC (1751455094.831768) - 2025-07-02 11:18:22.320 UTC (1751455102.320251) (duration: 7.488 s)
Packets in overlapping window: port3=758, port4=759

Port 3 → 4:
  Matched: 758  Dropped: 0
  Processing latency (ms): min=0.034 max=79.933 avg=0.825

Port 4 → 3:
  Matched: 758  Dropped: 1
  Processing latency (ms): min=0.036 max=79.935 avg=0.880

First 5 dropped port 3 → 4:

First 5 dropped port 4 → 3:
  Frame #784 2025-07-02 11:18:22.320 UTC ('UDP', '10.161.64.201', 32536, '10.3.12.202', 10733, b'\x80\x08G\xeb\xd9n\xfb -\x12\xdb\x16@v~eee{|}vL_\xd7\xc0\xf4\xf6\xf0\xf3\xf0\xf1\xf6\xcf\xd6P\\ZYSQT\xdc\xde\xc0\xf7\xf0\xf0\xf6\xca\xc4\xde\xd7]@qyeeexrst@]\xd0\xc3\xca\xf6\xf0\xf0\xf0\xf3\xf6\xc6TP\\[RWW\xd7\xd8\xda\xce\xf6\xf0\xf6\xf4\xcc\xdb\xddWEKsxeez~rpuGR\xdd\xce\xf4\xf1\xf3\xf3\xf1\xf1\xf5\xdbVP\\YSUW\xd6\xdb\xc4\xc8\xf1\xf0\xf6\xf5\xc3\xde\xd0QEJrzeee|sqJDS\xd9\xce\xf4\xf0\xf3\xf3\xf0\xf1\xca\xddWPY_QTW\xd2\xd9\xc7\xf4\xf0')

Top 10 highest latency port 3 → 4:
  2025-07-02 11:18:17.764 UTC (#321) → 2025-07-02 11:18:17.844 UTC (#324) latency: 79.933 ms
  2025-07-02 11:18:17.764 UTC (#322) → 2025-07-02 11:18:17.844 UTC (#325) latency: 79.933 ms
  2025-07-02 11:18:17.764 UTC (#323) → 2025-07-02 11:18:17.844 UTC (#326) latency: 79.933 ms
  2025-07-02 11:18:16.157 UTC (#137) → 2025-07-02 11:18:16.167 UTC (#137) latency: 9.175 ms
  2025-07-02 11:18:17.897 UTC (#339) → 2025-07-02 11:18:17.905 UTC (#339) latency: 8.251 ms
  2025-07-02 11:18:16.136 UTC (#135) → 2025-07-02 11:18:16.143 UTC (#135) latency: 7.805 ms
  2025-07-02 11:18:17.396 UTC (#287) → 2025-07-02 11:18:17.400 UTC (#287) latency: 4.849 ms
  2025-07-02 11:18:17.374 UTC (#285) → 2025-07-02 11:18:17.379 UTC (#285) latency: 4.679 ms
  2025-07-02 11:18:17.935 UTC (#343) → 2025-07-02 11:18:17.939 UTC (#343) latency: 4.059 ms
  2025-07-02 11:18:17.921 UTC (#341) → 2025-07-02 11:18:17.924 UTC (#342) latency: 3.322 ms
Average latency port 3 → 4: -0.023 ms

Top 10 highest latency port 4 → 3:
  2025-07-02 11:18:17.764 UTC (#322) → 2025-07-02 11:18:17.844 UTC (#325) latency: 79.935 ms
  2025-07-02 11:18:17.764 UTC (#323) → 2025-07-02 11:18:17.844 UTC (#326) latency: 79.934 ms
  2025-07-02 11:18:17.764 UTC (#321) → 2025-07-02 11:18:17.844 UTC (#324) latency: 79.933 ms
  2025-07-02 11:18:17.905 UTC (#340) → 2025-07-02 11:18:17.921 UTC (#340) latency: 15.953 ms
  2025-07-02 11:18:17.845 UTC (#334) → 2025-07-02 11:18:17.857 UTC (#334) latency: 12.524 ms
  2025-07-02 11:18:16.085 UTC (#130) → 2025-07-02 11:18:16.095 UTC (#130) latency: 9.742 ms
  2025-07-02 11:18:15.181 UTC (#40) → 2025-07-02 11:18:15.188 UTC (#40) latency: 7.430 ms
  2025-07-02 11:18:16.143 UTC (#136) → 2025-07-02 11:18:16.149 UTC (#136) latency: 5.586 ms
  2025-07-02 11:18:17.885 UTC (#338) → 2025-07-02 11:18:17.889 UTC (#338) latency: 3.903 ms
  2025-07-02 11:18:17.921 UTC (#341) → 2025-07-02 11:18:17.924 UTC (#342) latency: 3.323 ms
Average latency port 4 → 3: 0.023 ms
 ``` </pre>
