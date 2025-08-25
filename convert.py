#!/usr/bin/env python3

import argparse
import dpkt
import socket
import pandas as pd
import numpy as np
import sys
from collections import defaultdict

FEATURES = [
    'Init_Win_bytes_forward',
    'Destination Port',
    'Packet Length Variance',
    'Average Packet Size',
    'Packet Length Std',
    'Max Packet Length',
    'Subflow Fwd Bytes',
    'Bwd Packet Length Max',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Mean',
    'Fwd Packet Length Min',
    'Bwd Packet Length Std',
    'Bwd Packet Length Min',
    'Init_Win_bytes_backward',
    'Fwd Packet Length Std',
    'Packet Length Mean',
    'Fwd Header Length',
    'Fwd Packet Length Max',
    'Fwd Header Length.1',
    'Bwd Header Length'
]

class FlowStats:
    __slots__ = (
        'dst_port', 'pkt_lens_f', 'pkt_lens_b', 'hdr_f', 'hdr_b',
        'win_f', 'win_b', 'bytes_f', 'start', 'end'
    )

    def __init__(self, dst_port):
        self.dst_port = dst_port
        self.pkt_lens_f = []
        self.pkt_lens_b = []
        self.hdr_f = []
        self.hdr_b = []
        self.win_f = None
        self.win_b = None
        self.bytes_f = 0
        self.start = None
        self.end = None

    def add(self, ts, fwd, pkt_len, hdr_len, win):
        if self.start is None:
            self.start = ts
        self.end = ts
        if fwd:
            self.pkt_lens_f.append(pkt_len)
            self.hdr_f.append(hdr_len)
            self.bytes_f += pkt_len
            if self.win_f is None and win is not None:
                self.win_f = win
        else:
            self.pkt_lens_b.append(pkt_len)
            self.hdr_b.append(hdr_len)
            if self.win_b is None and win is not None:
                self.win_b = win

    def to_row(self):
        all_lens = self.pkt_lens_f + self.pkt_lens_b
        if not all_lens:
            return None
        np_all = np.asarray(all_lens, dtype=np.float64)
        np_f = np.asarray(self.pkt_lens_f, dtype=np.float64) if self.pkt_lens_f else np.array([0])
        np_b = np.asarray(self.pkt_lens_b, dtype=np.float64) if self.pkt_lens_b else np.array([0])
        row = {
            'Init_Win_bytes_forward': self.win_f or 0,
            'Destination Port': self.dst_port,
            'Packet Length Variance': float(np.var(np_all)),
            'Average Packet Size': float(np.mean(np_all)),
            'Packet Length Std': float(np.std(np_all)),
            'Max Packet Length': int(np.max(np_all)),
            'Subflow Fwd Bytes': self.bytes_f,
            'Bwd Packet Length Max': int(np.max(np_b)),
            'Fwd Packet Length Mean': float(np.mean(np_f)),
            'Bwd Packet Length Mean': float(np.mean(np_b)),
            'Fwd Packet Length Min': int(np.min(np_f)),
            'Bwd Packet Length Std': float(np.std(np_b)),
            'Bwd Packet Length Min': int(np.min(np_b)),
            'Init_Win_bytes_backward': self.win_b or 0,
            'Fwd Packet Length Std': float(np.std(np_f)),
            'Packet Length Mean': float(np.mean(np_all)),
            'Fwd Header Length': float(np.mean(self.hdr_f) if self.hdr_f else 0),
            'Fwd Packet Length Max': int(np.max(np_f)),
            'Fwd Header Length.1': float(np.mean(self.hdr_f) if self.hdr_f else 0),
            'Bwd Header Length': float(np.mean(self.hdr_b) if self.hdr_b else 0)
        }
        return row

def inet_ntoa(addr):
    return socket.inet_ntoa(addr) if isinstance(addr, bytes) else addr

def main(pcap_path, out_path, verbose=False):
    flows = {}
    processed = 0
    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            processed += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                proto = ip.p
                if proto not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
                    continue
                sport, dport = None, None
                hdr_len = 0
                win = None
                if proto == dpkt.ip.IP_PROTO_TCP:
                    tcp = ip.data
                    sport, dport = tcp.sport, tcp.dport
                    hdr_len = tcp.off * 4
                    win = tcp.win
                else:
                    udp = ip.data
                    sport, dport = udp.sport, udp.dport
                    hdr_len = 8
                src = inet_ntoa(ip.src)
                dst = inet_ntoa(ip.dst)
                key_fwd = (src, sport, dst, dport, proto)
                key_rev = (dst, dport, src, sport, proto)
                if key_fwd in flows:
                    key = key_fwd
                    fwd = True
                elif key_rev in flows:
                    key = key_rev
                    fwd = False
                else:
                    key = key_fwd
                    fwd = True
                    flows[key] = FlowStats(dport)
                pkt_len = len(buf)
                flows[key].add(ts, fwd, pkt_len, hdr_len, win)
            except Exception:
                continue
            if verbose and processed % 100000 == 0:
                print(f"Processed {processed} packets … flows={len(flows)}", file=sys.stderr)
    rows = [fs.to_row() for fs in flows.values() if fs.to_row() is not None]
    df = pd.DataFrame(rows, columns=FEATURES)
    df.to_csv(out_path, index=False)
    if verbose:
        print(f"Wrote {len(df)} flow records to {out_path}", file=sys.stderr)

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description="PCAP to CSV")
    ap.add_argument('--pcap', required=True, help="Input .pcap")
    ap.add_argument('--output', required=True, help="Output .csv")
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()
    main(args.pcap, args.output, args.verbose)
