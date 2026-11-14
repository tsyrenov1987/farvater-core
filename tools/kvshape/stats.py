#!/usr/bin/env python3
import json, sys, glob, os, collections, statistics as st
D = sys.argv[1]
def load(lab):
    c = json.load(open(f'{D}/{lab}.json'))
    c = max(c, key=lambda x: sum(r[2] for r in x['down']) + sum(r[2] for r in x['up']))
    return c
def recs(c, d): return [r for r in c[d] if r[1] == 23]
def dist(a, b):
    ha, hb = collections.Counter(), collections.Counter()
    for v in a: ha[v // 128] += 1 / len(a)
    for v in b: hb[v // 128] += 1 / len(b)
    return sum(max(0, v - hb[k]) for k, v in ha.items())
def line(name, r):
    L = [x[2] for x in r]
    if not L: return f'{name:26s} нет записей'
    cnt = collections.Counter(L); top = ', '.join(f'{v}:{100*n/len(L):.0f}%' for v, n in cnt.most_common(3))
    s = sorted(L); T = [x[0] for x in r]; gaps = [b - a for a, b in zip(T, T[1:])]
    dur = T[-1] - T[0]
    big = sum(1 for g in gaps if g > 0.005)
    return (f'{name:26s} n={len(L):5d} байт={sum(L):8d} разных={len(cnt):4d} p10={s[len(s)//10]:5d} p50={s[len(s)//2]:5d} '
            f'<1000:{100*sum(1 for v in L if v<1000)/len(L):4.0f}% топ[{top}] длит={dur:5.2f}с пауз>5мс={big}')
kinds = [('get8', 'down8', 'down', 'up'), ('get1', 'down1', 'down', 'up'), ('post8', 'up8', 'up', 'down'), ('post1', 'up1', 'up', 'down')]
for ck, tk, fwd, rev in kinds:
    print(f'\n##### {ck} (Chrome) против {tk} (туннель); основное направление: {fwd}')
    runs = {}
    for who, k in (('chrome', ck), ('tun-moderate', tk), ('tun-site', tk)):
        for f in sorted(glob.glob(f'{D}/{who}-{k}-*.json')):
            lab = os.path.basename(f)[:-5]; c = load(lab); runs.setdefault(who, []).append((lab, c))
            print(line(lab + ' →', recs(c, fwd))); print(line('   обратное', recs(c, rev)), f"пакетов вниз/вверх {c['pk_down']}/{c['pk_up']}")
    ch = runs.get('chrome', [])
    pool = [x[2] for _, c in ch for x in recs(c, fwd)]; rpool = [x[2] for _, c in ch for x in recs(c, rev)]
    for i in range(len(ch)):
        for j in range(i + 1, len(ch)):
            print(f'  расстояние Chrome–Chrome {i+1}-{j+1}: осн. {dist([x[2] for x in recs(ch[i][1], fwd)], [x[2] for x in recs(ch[j][1], fwd)]):.2f}, обр. {dist([x[2] for x in recs(ch[i][1], rev)], [x[2] for x in recs(ch[j][1], rev)]):.2f}')
    for who in ('tun-moderate', 'tun-site'):
        for lab, c in runs.get(who, []):
            a = [x[2] for x in recs(c, fwd)]; b = [x[2] for x in recs(c, rev)]
            if a and pool: print(f'  расстояние {lab} до Chrome: осн. {dist(a, pool):.2f}, обр. {dist(b, rpool) if b and rpool else float("nan"):.2f}')
