#!/usr/bin/env python3
"""memecoin-dd · поиск кандидатов (этап 0). Только публичные API.
Использование: python3 discover.py [--min-mcap 10000] [--max-mcap 500000] [--max-age-h 72] [--min-age-h 1]
                                   [--min-liq 8000] [--min-vol24 30000] [--max-h6 300] [--min-h6 -35] [--limit 25] [--json out.json]
                                   [--exclude CA1,CA2,...] [--exclude-file path]   # уже разобранные (журнал) — не выводить повторно
Источники: pump.fun (по капитализации и по последней сделке, ~1000 монет), DexScreener token-profiles/boosts (Solana).
Фильтр: окно капы, возраст, ликвидность, объём, не парабола (Δ6h ≤ max-h6) и не обвал (Δ6h ≥ min-h6). Сортировка — по vol24/mcap (живость), затем по числу сделок.
"""
import json, os, sys, time, urllib.request

def arg(name, default):
    a = sys.argv
    return type(default)(a[a.index(name) + 1]) if name in a else default

def excluded():
    ex = set(x.strip() for x in arg("--exclude", "").split(",") if x.strip())
    p = arg("--exclude-file", "")
    if p and os.path.exists(p): ex |= set(l.strip().split()[0] for l in open(p) if l.strip() and not l.startswith("#"))
    return ex

def get(u):
    req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r: return json.loads(r.read().decode())
    except Exception: return None

def main():
    lo, hi = arg("--min-mcap", 10000), arg("--max-mcap", 500000)
    max_age, min_age = arg("--max-age-h", 72), arg("--min-age-h", 1)
    min_liq, min_vol = arg("--min-liq", 8000), arg("--min-vol24", 30000)
    max_h6, min_h6, limit = arg("--max-h6", 300), arg("--min-h6", -35), arg("--limit", 25)
    now = time.time() * 1000
    cands = {}
    for sort in ("market_cap", "last_trade_timestamp"):
        for off in range(0, 1000, 50):
            r = get(f"https://frontend-api-v3.pump.fun/coins?offset={off}&limit=50&sort={sort}&order=DESC&includeNsfw=false")
            if not isinstance(r, list) or not r: break
            for c in r:
                age = (now - (c.get("created_timestamp") or 0)) / 3.6e6; mc = c.get("usd_market_cap") or 0
                if min_age <= age <= max_age and lo * 0.5 <= mc <= hi * 2: cands.setdefault(c["mint"], "pump")
            if sort == "market_cap" and r and (r[-1].get("usd_market_cap") or 0) < lo * 0.5: break
    for u, tag in (("https://api.dexscreener.com/token-profiles/latest/v1", "dex-profile"), ("https://api.dexscreener.com/token-boosts/latest/v1", "dex-boost")):
        for x in (get(u) or []):
            if x.get("chainId") == "solana": cands.setdefault(x["tokenAddress"], tag)
    ex = excluded(); skipped = [m for m in cands if m in ex]
    for m in skipped: cands.pop(m)
    print(f"сырых кандидатов: {len(cands)} · окно капы ${lo:,}–${hi:,} · возраст {min_age}–{max_age}ч" + (f" · исключено (уже в журнале): {len(skipped)}" if skipped else ""), file=sys.stderr)
    rows = []
    for mint, src in cands.items():
        d = get(f"https://api.dexscreener.com/tokens/v1/solana/{mint}")
        if not isinstance(d, list) or not d: continue
        p = max(d, key=lambda q: (q.get("liquidity") or {}).get("usd") or 0)
        ts = [q.get("pairCreatedAt") for q in d if q.get("pairCreatedAt")]; age = (now - min(ts)) / 3.6e6 if ts else None
        mcap = p.get("marketCap") or p.get("fdv") or 0; liq = (p.get("liquidity") or {}).get("usd") or 0
        v24 = (p.get("volume") or {}).get("h24") or 0; ch = p.get("priceChange") or {}; tx = p.get("txns") or {}
        h6 = ch.get("h6") if ch.get("h6") is not None else ch.get("h24")
        bonding = p.get("dexId") in ("pumpfun", "fourmeme", "moonshot", "launchlab")
        if not (lo <= mcap <= hi): continue
        if age is not None and not (min_age <= age <= max_age): continue
        if not bonding and liq < min_liq: continue
        if v24 < min_vol: continue
        if h6 is not None and not (min_h6 <= h6 <= max_h6): continue
        t24 = (tx.get("h24") or {}); buys, sells = t24.get("buys", 0), t24.get("sells", 0)
        soc = [s.get("url") for s in ((p.get("info") or {}).get("socials") or [])][:2]
        rows.append({"symbol": p["baseToken"]["symbol"], "ca": mint, "src": src, "dex": p.get("dexId"), "age_h": round(age, 1) if age else None, "mcap": round(mcap), "liq": round(liq),
                     "vol24": round(v24), "vol_mcap": round(v24 / max(mcap, 1), 2), "tx24": buys + sells, "buy_pct": round(buys / max(buys + sells, 1) * 100), "h1": ch.get("h1"), "h6": h6, "h24": ch.get("h24"),
                     "boosts": (p.get("boosts") or {}).get("active", 0), "socials": soc})
    rows.sort(key=lambda r: (-min(r["vol_mcap"], 20), -r["tx24"]))
    for r in rows[:limit]:
        print(f"{r['symbol'][:10]:<11}{r['ca']}  {r['dex'][:9]:<10}{str(r['age_h']) + 'ч':>7}  mcap ${r['mcap']:>8,}  liq ${r['liq']:>7,}  vol24 ${r['vol24']:>9,} ({r['vol_mcap']:>5}×)  tx {r['tx24']:>5} buy{r['buy_pct']:>3}%  Δ1h {str(r['h1']):>6}%  Δ6h {str(r['h6']):>6}%  Δ24h {str(r['h24']):>7}%  boost {r['boosts']:<4} {r['socials']}")
    if "--json" in sys.argv: json.dump(rows[:limit], open(arg("--json", "cands.json"), "w"), ensure_ascii=False)

if __name__ == "__main__": main()
