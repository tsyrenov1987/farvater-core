#!/usr/bin/env python3
# pcap (Ethernet, IPv4/TCP) -> записи TLS по соединениям и направлениям: [время, тип, длина]
import struct, sys, json
def parse(path, sip):
    f = open(path, 'rb'); gh = f.read(24)
    magic = struct.unpack('<I', gh[:4])[0]
    ns = magic == 0xa1b23c4d
    link = struct.unpack('<I', gh[20:24])[0]
    conns = {}
    while True:
        h = f.read(16)
        if len(h) < 16: break
        ts, frac, incl, orig = struct.unpack('<IIII', h)
        d = f.read(incl); t = ts + frac / (1e9 if ns else 1e6)
        off = 14 if link == 1 else (16 if link == 113 else 20)
        if d[off] >> 4 != 4: continue
        ihl = (d[off] & 15) * 4; tot = struct.unpack('>H', d[off+2:off+4])[0]
        if d[off+9] != 6: continue
        src = '.'.join(map(str, d[off+12:off+16])); dst = '.'.join(map(str, d[off+16:off+20]))
        tcp = off + ihl; sp, dp, seq = struct.unpack('>HHI', d[tcp:tcp+8])
        doff = (d[tcp+12] >> 4) * 4; flags = d[tcp+13]
        pay = d[tcp+doff: off+tot] if tot else d[tcp+doff:]
        down = src == sip
        key = (dst, dp, sp) if down else (src, sp, dp)
        c = conns.setdefault(key, {'t0': t, 'pk': [0, 0], 'd': [dict(nxt=None, buf={}, hdr=b'', left=0, recs=[]) for _ in range(2)]})
        s = c['d'][0 if down else 1]
        if flags & 2: s['nxt'] = (seq + 1) & 0xffffffff; continue
        if not pay: continue
        c['pk'][0 if down else 1] += 1
        if s['nxt'] is None: s['nxt'] = seq
        s['buf'][seq] = pay
        while True:
            # сегмент, покрывающий nxt (ретрансляции и перекрытия отбрасываются)
            hit = None
            for q in list(s['buf']):
                delta = (s['nxt'] - q) & 0xffffffff
                if delta < len(s['buf'][q]): hit = (q, delta); break
                if delta < 0x80000000: del s['buf'][q]
            if not hit: break
            b = s['buf'].pop(hit[0])[hit[1]:]; s['nxt'] = (s['nxt'] + len(b)) & 0xffffffff
            while b:
                if s['left']:
                    n = min(s['left'], len(b)); s['left'] -= n; b = b[n:]
                    if s['left'] == 0: s['recs'][-1][0] = round(t - c['t0'], 4)
                    continue
                n = min(5 - len(s['hdr']), len(b)); s['hdr'] += b[:n]; b = b[n:]
                if len(s['hdr']) == 5:
                    L = s['hdr'][3] << 8 | s['hdr'][4]; s['recs'].append([round(t - c['t0'], 4), s['hdr'][0], L]); s['left'] = L; s['hdr'] = b''
    out = []
    for k, c in conns.items():
        out.append({'peer': '%s:%d' % (k[0], k[1]), 'port': k[2], 'pk_down': c['pk'][0], 'pk_up': c['pk'][1],
                    'down': c['d'][0]['recs'], 'up': c['d'][1]['recs']})
    return out
if __name__ == '__main__':
    json.dump(parse(sys.argv[1], sys.argv[2]), sys.stdout)
