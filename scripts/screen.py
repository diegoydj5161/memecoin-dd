#!/usr/bin/env python3
"""memecoin-dd · этап 1 (детерминированный фильтр скама).
Использование:
  python3 screen.py <chain> <address> [--profile trench|fresh|established] [--json] [--save DIR] [--fast] [--rpc URL]   # --fast: без RPC-разбора дев-кошелька
  python3 screen.py --offline DIR [--profile ...]     # оценить ранее сохранённые сырые JSON
chain = dexscreener chainId: solana | ethereum | bsc | base | arbitrum | polygon | avalanche | optimism
Пороги: thresholds.json рядом со скриптом (переопределяет встроенные DEFAULTS).
Только публичные API без ключей: dexscreener, rugcheck (solana), gopluslabs, honeypot.is (evm), pump.fun.
v0.8 (08.09.2026): дев-кошелёк разбирается по адресу его токен-аккаунта (ATA выводится как PDA, история сигнатур
доступна и после закрытия) — иначе у токенов с DistributeCreatorFees окно 1000 сигнатур забито чужими свопами;
RPC с ретраями; отказ RPC в проверке спящих холдеров даёт NA, а не «0 из 10». Токены гонять ПОСЛЕДОВАТЕЛЬНО:
два параллельных прогона ловят 429 от публичного RPC.
"""
import hashlib, json, os, sys, time, urllib.request

CHAINS = {"solana": (None, None), "ethereum": ("1", 1), "bsc": ("56", 56), "base": ("8453", 8453),
          "arbitrum": ("42161", None), "polygon": ("137", None), "avalanche": ("43114", None), "optimism": ("10", None)}
LAUNCHPADS = {"pumpfun", "fourmeme", "moonshot", "launchlab", "believe", "boop", "bags", "virtuals", "letsbonk", "sunpump"}
BURN = {"0x0000000000000000000000000000000000000000", "0x000000000000000000000000000000000000dead", "0x0000000000000000000000000000000000000001"}
DEFAULTS = {
  "common": {"max_tax_pct": 10, "warn_tax_pct": 3, "max_transfer_fee_pct": 2, "established_mcap_usd": 1000000, "established_age_h": 72, "distributed_lp_providers": 20, "wash_vol_to_mcap": 3, "wash_max_holders": 1000,
             "dev_sold_pct_max": 50, "dev_snipe_sol_warn": 5, "dev_wallet_age_warn_h": 24, "dev_tx_sample": 80, "parabolic_h6_pct": 500, "parabolic_h24_pct": 1000, "off_ath_pct": 50, "dormant_top_max": 3, "dev_sold_min_sol": 1.0},
  "trench": {"min_mcap_usd": 8000, "max_top10_pct": 35, "max_single_holder_pct": 12, "max_insiders_pct": 15, "max_creator_pct": 5,
             "min_holders": 50, "max_creator_prior_tokens": 3, "min_txns24": 100, "hard": ["honeypot", "authorities", "tax", "creator_history", "insiders", "top10", "creator_pct", "dev_sold"]},
  "fresh": {"min_liq_usd": 8000, "min_lp_locked_pct": 90, "max_top10_pct": 30, "max_single_holder_pct": 10, "max_insiders_pct": 15, "max_creator_pct": 5,
            "min_holders": 200, "max_creator_prior_tokens": 5, "min_vol24_usd": 20000, "min_txns24": 300, "min_vol24_to_liq": 0.5, "min_liq_to_mcap_pct": 3,
            "hard": ["honeypot", "authorities", "tax", "contract", "lp_locked", "top10", "insiders", "creator_pct", "liquidity", "dev_sold"]},
  "established": {"min_liq_usd": 50000, "min_lp_locked_pct": 80, "max_top10_pct": 25, "max_single_holder_pct": 8, "max_insiders_pct": 10, "max_creator_pct": 3,
                  "min_holders": 1500, "max_creator_prior_tokens": 10, "min_vol24_usd": 100000, "min_txns24": 1000, "min_vol24_to_liq": 0.2, "min_liq_to_mcap_pct": 1,
                  "hard": ["honeypot", "authorities", "tax", "contract", "liquidity"]}}

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"_err": str(e)[:120]}

RPC = sys.argv[sys.argv.index("--rpc") + 1] if "--rpc" in sys.argv else "https://api.mainnet-beta.solana.com"
def rpc(method, params, tries=3):
    """Публичный RPC отдаёт 429 при параллельных прогонах — ретрай с паузой; None = источник не ответил (NA), а не «пусто»."""
    for i in range(tries):
        req = urllib.request.Request(RPC, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r: j = json.loads(r.read().decode())
            if "error" in j and j["error"].get("code") in (429, -32429, -32005): raise Exception("rate")
            return j.get("result")
        except Exception: time.sleep(1.5 * (i + 1))
    return None

# --- адрес токен-аккаунта дева без внешних библиотек: base58 + PDA (sha256 + проверка «не на кривой» ed25519) ---
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for ch in s: n = n * 58 + _B58.index(ch)
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + n.to_bytes((n.bit_length() + 7) // 8, "big")
def b58encode(b):
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = _B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + s
_P = 2 ** 255 - 19; _D = (-121665 * pow(121666, _P - 2, _P)) % _P
def _on_curve(b):
    y = (int.from_bytes(b, "little") & ((1 << 255) - 1)) % _P
    u, v = (y * y - 1) % _P, (_D * y * y + 1) % _P
    x2 = u * pow(v, _P - 2, _P) % _P
    if x2 == 0: return True
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P: x = x * pow(2, (_P - 1) // 4, _P) % _P
    return (x * x - x2) % _P == 0
def ata_address(owner, mint, token_program):
    seeds = b58decode(owner) + b58decode(token_program) + b58decode(mint)
    for bump in range(255, -1, -1):
        h = hashlib.sha256(seeds + bytes([bump]) + b58decode("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL") + b"ProgramDerivedAddress").digest()
        if not _on_curve(h): return b58encode(h)
TOKEN_PROGRAMS = ("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")

def dev_activity(creator, mint, sample=80, created_ts=None):
    """Solana: что дев-кошелёк делал с этим минтом — покупка при создании, продажи, переводы токенов, возраст кошелька.
    Точный путь: история его токен-аккаунта (ATA) по минту. ATA выводится как PDA, поэтому история читается и у закрытого
    аккаунта; «ATA не создавался» = дев токенов не держал вовсе. Окна по кошельку — только запасной путь: у токенов
    PumpSwap кошелёк дева упоминается в каждом DistributeCreatorFees, и 1000 сигнатур не доходят до его сделок."""
    sigs = rpc("getSignaturesForAddress", [creator, {"limit": 1000}])
    out = {"rpc_ok": sigs is not None, "tx_total": len(sigs or []), "wallet_age_h": (time.time() - sigs[-1]["blockTime"]) / 3600 if sigs else None, "sample": 0, "mint_tx": 0,
           "buy_sol": 0.0, "sell_sol": 0.0, "sells": 0, "first_sell": None, "tokens_in": 0.0, "tokens_out": 0.0, "moved_out": 0.0, "sol_balance": None, "via": "wallet", "ata_history": "unknown"}
    sigs = sigs or []
    try: out["creator_is_pda"] = not _on_curve(b58decode(creator))     # адрес вне кривой = PDA программы (лаунчер), подписывать и продавать сам не может
    except Exception: out["creator_is_pda"] = None
    bal = rpc("getBalance", [creator]); out["sol_balance"] = bal["value"] / 1e9 if isinstance(bal, dict) else None
    ta = rpc("getTokenAccountsByOwner", [creator, {"mint": mint}, {"encoding": "jsonParsed"}]) or {}
    live = [x["pubkey"] for x in ta.get("value", [])]
    out["ata_balance"] = sum(f(x["account"]["data"]["parsed"]["info"]["tokenAmount"].get("uiAmount")) for x in ta.get("value", []))
    atas = live or [a for a in (ata_address(creator, mint, p) for p in TOKEN_PROGRAMS) if a]   # закрытый ATA: адрес детерминирован, сигнатуры остаются
    ata_sigs = {}; ata_rpc_ok = True
    for a in atas:
        r = rpc("getSignaturesForAddress", [a, {"limit": 1000}])
        if r is None: ata_rpc_ok = False
        for x in r or []: ata_sigs[x["signature"]] = x
    out["ata_history"] = "live" if live else ("closed" if ata_sigs else ("never" if ata_rpc_ok else "unknown"))
    out["ata_sigs"] = len(ata_sigs); out["ata_capped"] = len(ata_sigs) >= 1000   # ATA большого токена трогают чужие tx — история обрезана, старт мог выпасть
    origin = []
    if out["ata_capped"] and atas:                                          # листаем историю ATA назад до её начала: первые tx = создание аккаунта и покупка дева
        a = atas[0]; oldest = min(ata_sigs.values(), key=lambda x: (x.get("blockTime") or 0))
        for _ in range(3):
            page = rpc("getSignaturesForAddress", [a, {"limit": 1000, "before": oldest["signature"]}])
            if not page: break
            oldest = page[-1]
            if len(page) < 1000: origin = page[-20:]; break
        out["ata_origin_found"] = bool(origin)
    if created_ts: sigs = [x for x in sigs if (x.get("blockTime") or 0) >= created_ts - 3600] or sigs   # окно жизни токена: старые tx кошелька к минту отношения не имеют
    out["wallet_sigs_lifetime"] = len(sigs)
    creation = [x for x in sigs if created_ts and created_ts - 120 <= (x.get("blockTime") or 0) <= created_ts + 900][-25:][::-1]   # первые 15 мин жизни токена, старейшие вперёд: здесь стартовая покупка дева
    common = [x for x in sigs if x["signature"] in ata_sigs]              # tx, где участвуют и кошелёк дева, и его токен-аккаунт = его собственные сделки/переводы
    seen = set(); dedup = lambda xs: [x for x in xs if not (x["signature"] in seen or seen.add(x["signature"]))]
    if ata_sigs and not out["ata_capped"]:
        out["via"] = "ata"; by_time = sorted(ata_sigs.values(), key=lambda x: (x.get("blockTime") or 0))
        todo = by_time if len(by_time) <= sample else by_time[:sample // 2] + by_time[-(sample // 2):]   # вся история ATA: создание/покупка … продажи/переводы
    elif common: out["via"] = "wallet∩ata"; todo = dedup(creation + origin + common[:sample - len(creation) - len(origin)] + ([] if created_ts else sigs[-20:]))
    elif sigs: out["via"] = "wallet+origin" if origin else "wallet"; todo = dedup(creation + origin + ((sigs[:sample // 2] + sigs[-(sample // 2):]) if len(sigs) > sample else sigs))   # окно ATA забито чужими tx — идём по кошельку: новейшие + старейшие
    elif ata_sigs: out["via"] = "ata"; todo = dedup(origin + sorted(ata_sigs.values(), key=lambda x: -(x.get("blockTime") or 0))[:sample])
    else: todo = []
    t0 = time.time()
    for sg in todo:
        if time.time() - t0 > 50: break
        tx = rpc("getTransaction", [sg["signature"], {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}])
        out["sample"] += 1
        if not tx or not tx.get("meta"): continue
        keys = [a.get("pubkey") for a in tx["transaction"]["message"]["accountKeys"]]
        if creator not in keys: continue
        pre = {b["accountIndex"]: f((b.get("uiTokenAmount") or {}).get("uiAmount")) for b in tx["meta"].get("preTokenBalances") or [] if b.get("mint") == mint and b.get("owner") == creator}
        post = {b["accountIndex"]: f((b.get("uiTokenAmount") or {}).get("uiAmount")) for b in tx["meta"].get("postTokenBalances") or [] if b.get("mint") == mint and b.get("owner") == creator}
        if not pre and not post and mint not in keys: continue
        tdelta = sum(post.values()) - sum(pre.values())
        i = keys.index(creator); sdelta = (tx["meta"]["postBalances"][i] - tx["meta"]["preBalances"][i]) / 1e9
        out["mint_tx"] += 1
        if tdelta > 0: out["tokens_in"] += tdelta
        if tdelta < 0: out["tokens_out"] += -tdelta
        if sdelta < -0.01 and tdelta >= 0: out["buy_sol"] += -sdelta
        elif sdelta > 0.01 and tdelta <= 0: out["sell_sol"] += sdelta; out["sells"] += 1; out["first_sell"] = out["first_sell"] or sg["blockTime"]
        elif tdelta < 0 and sdelta <= 0.01: out["moved_out"] += -tdelta; out["first_move"] = out.get("first_move") or sg["blockTime"]   # ушли токены, SOL не пришёл (комиссия/рента за ATA получателя) = перевод
    return out

def fetch_all(chain, addr):
    gp, hp = CHAINS[chain]
    raw = {"chain": chain, "address": addr, "fetched_at": int(time.time()),
           "dex": get(f"https://api.dexscreener.com/tokens/v1/{chain}/{addr}"),
           "orders": get(f"https://api.dexscreener.com/orders/v1/{chain}/{addr}")}
    if chain == "solana":
        raw["rugcheck"] = get(f"https://api.rugcheck.xyz/v1/tokens/{addr}/report")
        raw["rugcheck_summary"] = get(f"https://api.rugcheck.xyz/v1/tokens/{addr}/report/summary")
        g = get(f"https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses={addr}")
        raw["goplus"] = (g.get("result") or {}).get(addr) or g
        if addr.endswith("pump") or any(p.get("dexId") in ("pumpfun", "pumpswap") for p in raw["dex"] if isinstance(raw["dex"], list)):
            raw["pumpfun"] = get(f"https://frontend-api-v3.pump.fun/coins/{addr}")
        creator = (raw["rugcheck"] or {}).get("creator") or (raw.get("pumpfun") or {}).get("creator")
        pf_ts = f((raw.get("pumpfun") or {}).get("created_timestamp")) / 1000 if isinstance(raw.get("pumpfun"), dict) else 0
        dx_ts = min([f(p.get("pairCreatedAt")) for p in raw["dex"] if isinstance(p, dict) and p.get("pairCreatedAt")] or [0]) / 1000 if isinstance(raw["dex"], list) else 0
        created_ts = min([t for t in (pf_ts, dx_ts) if t > 0] or [0]) or None
        if creator and "--fast" not in sys.argv: raw["dev_activity"] = dev_activity(creator, addr, DEFAULTS["common"]["dev_tx_sample"], created_ts)
        if "--fast" not in sys.argv and isinstance(raw["rugcheck"], dict):
            known = raw["rugcheck"].get("knownAccounts") or {}; dormant = []; checked = 0; failed = 0
            for h in (raw["rugcheck"].get("topHolders") or [])[:14]:
                if known.get(h.get("owner")) or h.get("owner") == creator: continue
                checked += 1; sg = rpc("getSignaturesForAddress", [h["owner"], {"limit": 1}])
                if sg == []: dormant.append((h["owner"], h.get("pct")))
                if sg is None: failed += 1                                  # RPC не ответил — это не «активный кошелёк»
                if checked >= 10: break
            raw["dormant_top"] = {"checked": checked, "dormant": dormant, "rpc_failed": failed}
    else:
        g = get(f"https://api.gopluslabs.io/api/v1/token_security/{gp}?contract_addresses={addr}")
        raw["goplus"] = (g.get("result") or {}).get(addr.lower()) or g
        if hp: raw["honeypot"] = get(f"https://api.honeypot.is/v2/IsHoneypot?address={addr}&chainID={hp}")
    return raw

def f(x, d=0.0):
    try: return float(x)
    except Exception: return d

def load_thresholds():
    t = json.loads(json.dumps(DEFAULTS))
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "thresholds.json")
    if os.path.exists(p):
        for k, v in json.load(open(p)).items(): t.setdefault(k, {}).update(v)
    return t

def extract(raw):
    m = {"chain": raw["chain"], "address": raw["address"], "sources": [], "socials": {}, "risks": [], "notes": []}
    dex = raw.get("dex") if isinstance(raw.get("dex"), list) else []
    if dex:
        m["sources"].append("dexscreener")
        main = max(dex, key=lambda p: f((p.get("liquidity") or {}).get("usd")))
        m.update(symbol=main["baseToken"].get("symbol"), name=main["baseToken"].get("name"), price=f(main.get("priceUsd")),
                 dex_ids=sorted({p.get("dexId") for p in dex}), pair=main.get("pairAddress"), pair_url=main.get("url"),
                 liq_usd=sum(f((p.get("liquidity") or {}).get("usd")) for p in dex), mcap=f(main.get("marketCap") or main.get("fdv")),
                 vol24=sum(f((p.get("volume") or {}).get("h24")) for p in dex), vol1h=sum(f((p.get("volume") or {}).get("h1")) for p in dex),
                 buys24=sum(int((p.get("txns") or {}).get("h24", {}).get("buys", 0)) for p in dex), sells24=sum(int((p.get("txns") or {}).get("h24", {}).get("sells", 0)) for p in dex),
                 chg={k: (main.get("priceChange") or {}).get(k) for k in ("h1", "h6", "h24")}, boosts=(main.get("boosts") or {}).get("active", 0))
        ts = [p.get("pairCreatedAt") for p in dex if p.get("pairCreatedAt")]
        m["age_h"] = (time.time() * 1000 - min(ts)) / 3.6e6 if ts else None
        info = main.get("info") or {}
        for s in info.get("socials") or []: m["socials"][s.get("type")] = s.get("url")
        if info.get("websites"): m["socials"]["website"] = info["websites"][0].get("url")
        m["is_bonding"] = all(d in LAUNCHPADS for d in m["dex_ids"])
    od = raw.get("orders") or {}
    m["dex_paid"] = sorted({o.get("type") for o in od.get("orders", []) if o.get("status") == "approved"}) if isinstance(od, dict) else []
    m["txns24"] = m.get("buys24", 0) + m.get("sells24", 0)
    rc = raw.get("rugcheck") or {}
    if rc and "mint" in rc:
        m["sources"].append("rugcheck")
        known = rc.get("knownAccounts") or {}
        creator = rc.get("creator")
        holders = []
        for h in rc.get("topHolders") or []:
            typ = (known.get(h.get("owner")) or known.get(h.get("address")) or {}).get("type")
            if typ and typ != "CREATOR": continue
            holders.append({"pct": f(h.get("pct")), "insider": bool(h.get("insider")), "creator": h.get("owner") == creator or typ == "CREATOR"})
        m.update(mint_authority=rc.get("mintAuthority"), freeze_authority=rc.get("freezeAuthority"), mutable=(rc.get("tokenMeta") or {}).get("mutable"),
                 transfer_fee_pct=f((rc.get("transferFee") or {}).get("pct")), holders_total=rc.get("totalHolders"), rug_score=rc.get("score_normalised"),
                 rugged=rc.get("rugged"), top10_pct=sum(h["pct"] for h in holders[:10]), max_holder_pct=max([h["pct"] for h in holders] or [0]),
                 insiders_pct=sum(h["pct"] for h in holders if h["insider"]), graph_insiders=rc.get("graphInsidersDetected"),
                 creator=creator, creator_pct=sum(h["pct"] for h in holders if h["creator"]) or f(rc.get("creatorBalance")) / max(f(rc.get("totalSupply") or (rc.get("token") or {}).get("supply")), 1) * 100,
                 launchpad=(rc.get("launchpad") or {}).get("name"), lp_providers=rc.get("totalLPProviders"), jup_verified=(rc.get("verification") or {}).get("jup_verified"))
        m["risks"] = [f"{r.get('name')} ({r.get('level')})" for r in rc.get("risks") or []]
        ct = rc.get("creatorTokens") or []
        m["creator_prior"] = {"count": len(ct), "dead": sum(1 for t in ct if f(t.get("marketCap")) < 5000), "best_mcap": max([f(t.get("marketCap")) for t in ct] or [0]),
                              "recent30d": sum(1 for t in ct if str(t.get("createdAt", ""))[:10] >= time.strftime("%Y-%m-%d", time.gmtime(time.time() - 30 * 86400)))}
        main_lp = [x for x in rc.get("markets") or [] if x.get("pubkey") == m.get("pair")]          # пул с наибольшей ликвидностью (DexScreener) — именно его LP важен
        if main_lp: m["lp_locked_pct"] = f((main_lp[0].get("lp") or {}).get("lpLockedPct")); m["lp_scope"] = f"основной пул {main_lp[0].get('marketType')}"
        else:
            m["lp_locked_pct"] = f((raw.get("rugcheck_summary") or {}).get("lpLockedPct"), None) if isinstance(raw.get("rugcheck_summary"), dict) else None
            m["lp_scope"] = "взвешенно по всем пулам RugCheck"
            if m["lp_locked_pct"] is None:
                mk = [x.get("lp") or {} for x in rc.get("markets") or []]
                m["lp_locked_pct"] = max([f(x.get("lpLockedPct")) for x in mk] or [0]) if mk else None
    gpl = raw.get("goplus") or {}
    if gpl and "_err" not in gpl and "code" not in gpl:
        m["sources"].append("goplus")
        if raw["chain"] == "solana":
            if "mint_authority" not in m:
                m["mint_authority"] = (gpl.get("mintable") or {}).get("status") == "1" or None
                m["freeze_authority"] = (gpl.get("freezable") or {}).get("status") == "1" or None
                hs = [f(h.get("percent")) * 100 for h in gpl.get("holders") or []]
                m.update(top10_pct=sum(hs[:10]), max_holder_pct=max(hs or [0]), holders_total=int(f(gpl.get("holder_count"))))
                lp = gpl.get("lp_holders") or []
                m["lp_locked_pct"] = sum(f(h.get("percent")) * 100 for h in lp if str(h.get("is_locked")) == "1")
                m["creator_pct"] = f((gpl.get("creators") or [{}])[0].get("percent")) * 100 if gpl.get("creators") else 0
        else:
            hs = [(f(h.get("percent")) * 100, h) for h in gpl.get("holders") or [] if str(h.get("is_contract")) != "1" and h.get("address") not in BURN and "lock" not in (h.get("tag") or "").lower()]
            lp = gpl.get("lp_holders") or []
            m.update(honeypot=str(gpl.get("is_honeypot")) == "1", buy_tax=f(gpl.get("buy_tax")) * 100, sell_tax=f(gpl.get("sell_tax")) * 100,
                     mintable=str(gpl.get("is_mintable")) == "1", proxy=str(gpl.get("is_proxy")) == "1", open_source=str(gpl.get("is_open_source")) == "1",
                     hidden_owner=str(gpl.get("hidden_owner")) == "1", take_back=str(gpl.get("can_take_back_ownership")) == "1",
                     owner=gpl.get("owner_address"), owner_renounced=(gpl.get("owner_address") or "").lower() in BURN | {""},
                     pausable=str(gpl.get("transfer_pausable")) == "1", blacklist=str(gpl.get("is_blacklisted")) == "1", cooldown=str(gpl.get("trading_cooldown")) == "1",
                     cannot_sell_all=str(gpl.get("cannot_sell_all")) == "1", anti_whale=str(gpl.get("is_anti_whale")) == "1", slippage_mod=str(gpl.get("slippage_modifiable")) == "1",
                     holders_total=int(f(gpl.get("holder_count"))), creator=gpl.get("creator_address"), creator_pct=f(gpl.get("creator_percent")) * 100,
                     owner_pct=f(gpl.get("owner_percent")) * 100, top10_pct=sum(x[0] for x in hs[:10]), max_holder_pct=max([x[0] for x in hs] or [0]),
                     lp_locked_pct=sum(f(h.get("percent")) * 100 for h in lp if str(h.get("is_locked")) == "1" or (h.get("address") or "").lower() in BURN | {raw["address"].lower()} or "lock" in (h.get("tag") or "").lower()),
                     lp_providers=int(f(gpl.get("lp_holder_count"))), same_creator_honeypots=gpl.get("honeypot_with_same_creator"))
            m["socials"].setdefault("website", None)
            m["risks"] = [k for k in ("hidden_owner", "take_back", "pausable", "blacklist", "cooldown", "cannot_sell_all", "anti_whale", "slippage_mod") if m.get(k)]
    hp = raw.get("honeypot") or {}
    if hp and "honeypotResult" in hp:
        m["sources"].append("honeypot.is")
        sim, ha = hp.get("simulationResult") or {}, hp.get("holderAnalysis") or {}
        m.update(honeypot=m.get("honeypot") or bool((hp["honeypotResult"] or {}).get("isHoneypot")), buy_tax=max(m.get("buy_tax", 0), f(sim.get("buyTax"))),
                 sell_tax=max(m.get("sell_tax", 0), f(sim.get("sellTax"))), hp_flags=hp.get("flags") or [],
                 sell_fail_pct=f(ha.get("failed")) / max(f(ha.get("holders")), 1) * 100, siphoned=int(f(ha.get("siphoned"))))
    da = raw.get("dev_activity")
    if isinstance(da, dict) and (da.get("sample") or da.get("ata_history") in ("never", "unknown")): m["dev"] = da
    if isinstance(raw.get("dormant_top"), dict): m["dormant_top"] = raw["dormant_top"]
    pf = raw.get("pumpfun") or {}
    if pf and "mint" in pf:
        m["sources"].append("pump.fun")
        m.update(pf_created_h=(time.time() * 1000 - f(pf.get("created_timestamp"))) / 3.6e6, pf_complete=pf.get("complete"), pf_replies=pf.get("reply_count"),
                 pf_ath_mcap=f(pf.get("ath_market_cap")), pf_banned=pf.get("is_banned"), pf_verified=pf.get("verified"))
        for k in ("twitter", "telegram", "website"):
            if pf.get(k): m["socials"].setdefault(k, pf[k])
        if not m.get("mcap"): m["mcap"] = f(pf.get("usd_market_cap"))
        m.setdefault("creator", pf.get("creator"))
    return m

def detect_profile(m, t):
    c = t["common"]
    if m.get("is_bonding") or (m.get("pf_complete") is False): return "trench"
    if f(m.get("age_h"), 0) >= c["established_age_h"] and f(m.get("mcap")) >= c["established_mcap_usd"]: return "established"
    return "fresh"      # микрокапы старше 72ч оцениваются порогами fresh: established-пороги ($50k ликв, 1500 холдеров) рассчитаны на $1M+

def evaluate(m, profile, t):
    p, c, checks = t[profile], t["common"], []
    def chk(key, ok, sev, text, na=False):
        checks.append({"key": key, "status": "NA" if na else ("OK" if ok else sev), "text": text})
    sol = m["chain"] == "solana"
    # контракт / минт
    if sol:
        chk("authorities", not m.get("mint_authority") and not m.get("freeze_authority"), "RED",
            f"mint authority {'✗' if not m.get('mint_authority') else '⚠ ЕСТЬ'} · freeze {'✗' if not m.get('freeze_authority') else '⚠ ЕСТЬ'}", na="mint_authority" not in m)
        chk("tax", f(m.get("transfer_fee_pct")) <= c["max_transfer_fee_pct"], "RED", f"transfer fee {f(m.get('transfer_fee_pct')):.1f}%", na="transfer_fee_pct" not in m)
        chk("mutable_meta", not m.get("mutable"), "YELLOW", "metadata mutable" if m.get("mutable") else "metadata immutable", na="mutable" not in m)
        chk("honeypot", True, "RED", "n/a (solana)", na=True)
        chk("contract", not m.get("rugged"), "RED", "RugCheck: rugged=true" if m.get("rugged") else "RugCheck: not rugged", na="rugged" not in m)
    else:
        chk("honeypot", not m.get("honeypot") and f(m.get("sell_fail_pct")) < 5, "RED",
            f"honeypot {'ДА' if m.get('honeypot') else 'нет'} · fail-sell {f(m.get('sell_fail_pct')):.1f}% · siphoned {m.get('siphoned', 0)}", na="honeypot" not in m)
        chk("tax", max(f(m.get("buy_tax")), f(m.get("sell_tax"))) <= c["max_tax_pct"], "RED", f"tax buy {f(m.get('buy_tax')):.1f}% / sell {f(m.get('sell_tax')):.1f}%", na="buy_tax" not in m)
        if "buy_tax" in m and c["warn_tax_pct"] < max(f(m.get("buy_tax")), f(m.get("sell_tax"))) <= c["max_tax_pct"]: chk("tax_warn", False, "YELLOW", "налог выше комфортного")
        bad = [k for k in ("mintable", "proxy", "hidden_owner", "take_back", "pausable", "blacklist", "cannot_sell_all", "cooldown") if m.get(k)]
        moot = m.get("owner_renounced", False) and not m.get("hidden_owner") and not m.get("proxy") and not m.get("take_back")
        chk("contract", (not bad or moot) and m.get("open_source", True), "RED", ("флаги: " + ", ".join(bad) + (" — но owner renounced, функции мертвы" if moot else "") if bad else "чистый") + ("" if m.get("open_source", True) else " · НЕ верифицирован"), na="mintable" not in m)
        if bad and moot: chk("contract_flags", False, "YELLOW", "в коде есть " + ", ".join(bad) + " (owner renounced)")
        chk("owner", m.get("owner_renounced", True), "YELLOW", "owner НЕ renounced: " + str(m.get("owner")) if not m.get("owner_renounced", True) else "ownership renounced", na="owner" not in m)
        if m.get("same_creator_honeypots") not in (None, "0", 0): chk("creator_history", False, "RED", f"у криейтора {m['same_creator_honeypots']} honeypot-контрактов")
    # ликвидность / LP
    if profile != "trench":
        chk("liquidity", f(m.get("liq_usd")) >= p["min_liq_usd"], "RED", f"ликв ${f(m.get('liq_usd')):,.0f} (мин {p['min_liq_usd']:,})", na="liq_usd" not in m)
        r = f(m.get("liq_usd")) / max(f(m.get("mcap")), 1) * 100
        chk("liq_to_mcap", r >= p["min_liq_to_mcap_pct"], "YELLOW", f"ликв/mcap {r:.1f}% (мин {p['min_liq_to_mcap_pct']}%)", na="liq_usd" not in m or not m.get("mcap"))
        if profile == "established" and int(f(m.get("lp_providers"))) >= c["distributed_lp_providers"]:
            chk("lp_locked", True, "OK", f"ликвидность распределена: {m.get('lp_providers')} LP-провайдеров (locked {f(m.get('lp_locked_pct')):.0f}%) — единый рагпулл невозможен, но крупные LP могут выйти")
        else:
            chk("lp_locked", f(m.get("lp_locked_pct")) >= p["min_lp_locked_pct"], "RED" if profile == "fresh" else "YELLOW", f"LP locked/burned {f(m.get('lp_locked_pct')):.0f}% (мин {p['min_lp_locked_pct']}%) · {m.get('lp_scope', '')} · LP-провайдеров {m.get('lp_providers')}", na=m.get("lp_locked_pct") is None)
        if profile == "established" and f(m.get("mcap")) < c["established_mcap_usd"]: chk("mcap_small", False, "YELLOW", f"токен старше 72ч с mcap ${f(m.get('mcap')):,.0f} < ${c['established_mcap_usd']:,} — микрокап: проверить, жив ли нарратив, или это зомби")
        chk("volume", f(m.get("vol24")) >= p["min_vol24_usd"] and m.get("txns24", 0) >= p["min_txns24"], "YELLOW",
            f"vol24 ${f(m.get('vol24')):,.0f} · txns24 {m.get('txns24', 0)} (мин ${p['min_vol24_usd']:,} / {p['min_txns24']})", na="vol24" not in m)
        chk("vol_to_liq", f(m.get("vol24")) / max(f(m.get("liq_usd")), 1) >= p["min_vol24_to_liq"], "YELLOW", f"vol24/ликв {f(m.get('vol24')) / max(f(m.get('liq_usd')), 1):.2f} (мин {p['min_vol24_to_liq']})", na="vol24" not in m)
    else:
        chk("mcap", f(m.get("mcap")) >= p["min_mcap_usd"], "YELLOW", f"mcap ${f(m.get('mcap')):,.0f} (мин {p['min_mcap_usd']:,})", na=not m.get("mcap"))
        chk("volume", m.get("txns24", 0) >= p["min_txns24"], "YELLOW", f"txns24 {m.get('txns24', 0)} (мин {p['min_txns24']})", na="txns24" not in m or not m.get("dex_ids"))
    if m.get("txns24"):
        b = m["buys24"] / m["txns24"] * 100
        chk("buy_ratio", 30 <= b <= 80, "YELLOW", f"buys {b:.0f}% от сделок (норма 30–80)")
        vm = f(m.get("vol24")) / max(f(m.get("mcap")), 1)
        if vm > c["wash_vol_to_mcap"] and int(f(m.get("holders_total"), 0)) < c["wash_max_holders"]: chk("wash", False, "YELLOW", f"vol24 = {vm:.1f}× mcap при {m.get('holders_total')} холдерах — объём-боты / wash, не считать за спрос")
    # холдеры
    chk("top10", f(m.get("top10_pct")) <= p["max_top10_pct"], "RED", f"top10 без LP {f(m.get('top10_pct')):.1f}% (макс {p['max_top10_pct']}%)", na="top10_pct" not in m)
    chk("single_holder", f(m.get("max_holder_pct")) <= p["max_single_holder_pct"], "RED", f"макс холдер {f(m.get('max_holder_pct')):.1f}% (макс {p['max_single_holder_pct']}%)", na="max_holder_pct" not in m)
    chk("insiders", f(m.get("insiders_pct")) <= p["max_insiders_pct"], "RED", f"инсайдеры {f(m.get('insiders_pct')):.1f}% (макс {p['max_insiders_pct']}%) · граф {m.get('graph_insiders')}", na="insiders_pct" not in m)
    chk("creator_pct", f(m.get("creator_pct")) <= p["max_creator_pct"], "RED", f"дев держит сейчас {f(m.get('creator_pct')):.1f}% (макс {p['max_creator_pct']}%) — 0% ≠ чисто, см. dev_sold", na="creator_pct" not in m)
    chk("holders_count", int(f(m.get("holders_total"))) >= p["min_holders"], "YELLOW", f"холдеров {m.get('holders_total')} (мин {p['min_holders']})", na=m.get("holders_total") is None)
    cp = m.get("creator_prior")
    if cp:
        bad_hist = cp["recent30d"] > p["max_creator_prior_tokens"] or any("rugged" in r.lower() for r in m["risks"])
        chk("creator_history", not bad_hist, "RED", f"прошлых токенов дева {cp['count']} (за 30д: {cp['recent30d']}, мёртвых {cp['dead']}, лучший ${cp['best_mcap']:,.0f}, макс за 30д {p['max_creator_prior_tokens']}) · " + ("RugCheck: история ругов" if any("rugged" in r.lower() for r in m["risks"]) else "без метки ругов"))
    # дев-кошелёк по факту (Solana RPC)
    da = m.get("dev")
    if da:
        bought, sold = da["buy_sol"], da["sell_sol"]
        pct = sold / bought * 100 if bought > 0 else (100.0 if sold > 0 else 0.0)
        fs = f" · первая продажа {time.strftime('%H:%M', time.gmtime(da['first_sell']))} UTC" if da.get("first_sell") else ""
        moved = da.get("moved_out", 0); moved_flag = moved >= 1e6 and moved >= 0.5 * da.get("tokens_in", 0)   # материально: ≥ 1M токенов (0.1% supply) и ≥ половины полученного
        mv = (f" · перевёл на другие кошельки {moved / max(da['tokens_in'], moved, 1) * 100:.0f}% полученных токенов ({moved / 1e6:.1f}M)" + (f" в {time.strftime('%H:%M', time.gmtime(da['first_move']))} UTC" if da.get("first_move") else "")) if moved >= 1e5 else ""
        hist = da.get("ata_history", "unknown")
        pda = " · криейтор = PDA программы-лаунчера (подписывать не может, операторские кошельки — другие)" if da.get("creator_is_pda") else ""
        if hist == "never":
            chk("dev_sold", True, "RED", "дев токенов не покупал вовсе (токен-аккаунт по минту не создавался) — это не «чисто», а перенос вопроса: кто купил первый блок (gmgn Bundlers/Snipers)" + pda)
        else:
            blind = da["via"] == "wallet" and da["tx_total"] >= 1000 and bought == 0 and sold == 0   # окно кошелька забито чужими tx (DistributeCreatorFees), сделки дева не видны
            tin, held = f(da.get("tokens_in")), f(da.get("ata_balance"))
            gone = tin >= 1e6 and held <= 0.5 * tin and not moved_flag and sold < c["dev_sold_min_sol"]   # купил при создании, а на балансе меньше половины — продажа/перевод прошли мимо выборки
            gn = f" · купил {tin / 1e6:.1f}M токенов, на балансе {held / 1e6:.1f}M (−{(1 - held / tin) * 100:.0f}%) — избавился вне разобранной выборки" if gone else ""
            chk("dev_sold", not ((pct >= c["dev_sold_pct_max"] and sold >= c["dev_sold_min_sol"]) or moved_flag or gone), "RED",
                (f"дев купил {bought:.1f} SOL, продал {sold:.1f} SOL за {da['sells']} сделок ({pct:.0f}% от покупки){fs}{mv}{gn} · баланс {f(da['sol_balance']):.1f} SOL · разобрано {da['sample']} tx ({da['via']}, ATA {hist}{', история обрезана' if da.get('ata_capped') else ''})")
                + (" · НЕ ИЗМЕРЕНО: окно 1000 сигнатур кошелька не доходит до сделок дева" if blind else ""), na=da["mint_tx"] == 0 or blind or hist == "unknown")
        chk("dev_snipe", bought <= c["dev_snipe_sol_warn"], "YELLOW", f"дев-покупка при создании {bought:.1f} SOL (порог {c['dev_snipe_sol_warn']})", na=bought == 0)
        chk("dev_wallet_age", f(da.get("wallet_age_h"), 1e9) >= c["dev_wallet_age_warn_h"], "YELLOW", f"возраст дев-кошелька {age_str(da.get('wallet_age_h'))} (порог {c['dev_wallet_age_warn_h']}ч)" + (" — по окну 1000 сигнатур, реальный возраст больше" if da["tx_total"] >= 1000 else ""), na=da.get("wallet_age_h") is None or da["tx_total"] >= 1000)
    corr = [r for r in m.get("risks", []) if "holder correlation" in str(r).lower() or "single holder" in str(r).lower()]
    if corr: chk("holder_correlation", False, "RED", "RugCheck: " + "; ".join(map(str, corr)) + " — одинаковые доли у топ-холдеров = размазанный по кошелькам флот одного оператора")
    dt = m.get("dormant_top")
    if dt and dt.get("checked"):
        n, pct, failed = len(dt["dormant"]), sum(f(x[1]) for x in dt["dormant"]), int(dt.get("rpc_failed") or 0)
        chk("dormant_holders", n < c["dormant_top_max"], "RED", f"{n} из {dt['checked']} топ-холдеров никогда не подписывали транзакций ({pct:.1f}% supply) — токены им переведены, не куплены: спрятанный бандл/команда"
            + (f" · RPC не ответил по {failed} из {dt['checked']} — спящие НЕ проверены, повторить прогон" if failed else ""), na=failed > 0)
    if f((m.get("chg") or {}).get("h6")) > c["parabolic_h6_pct"]: chk("parabolic", False, "YELLOW", f"Δ6h +{f(m['chg']['h6']):.0f}% — парабола, стадия раздачи вероятнее входа")
    if f((m.get("chg") or {}).get("h24")) > c["parabolic_h24_pct"]: chk("late_stage", False, "YELLOW", f"Δ24h +{f(m['chg']['h24']):.0f}% — поздняя стадия: вердикт этапа 2 не выше WATCH (Buttensor +1724% → −61% за 10ч)")
    if m.get("pf_ath_mcap") and m.get("mcap") and m["mcap"] < m["pf_ath_mcap"] * (1 - c["off_ath_pct"] / 100): chk("off_ath", False, "YELLOW", f"mcap ${f(m['mcap']):,.0f} = −{(1 - m['mcap'] / m['pf_ath_mcap']) * 100:.0f}% от ATH ${f(m['pf_ath_mcap']):,.0f} — уже был цикл")
    # соцсети / маркетинг
    soc = [k for k, v in m["socials"].items() if v]
    chk("socials", bool(soc), "YELLOW", ("есть: " + ", ".join(soc)) if soc else "соцсетей нет вообще")
    tw = str(m["socials"].get("twitter") or "")
    if "/status/" in tw or "/search?" in tw: chk("social_is_tweet", False, "YELLOW", "«twitter» в профиле — ссылка на чужой твит/поиск, а не аккаунт проекта: повод заимствован, сообщества нет")
    if m.get("dex_paid") or m.get("boosts"): chk("dex_paid", True, "OK", f"DEX paid: {', '.join(m['dex_paid']) or '—'} · boosts {m.get('boosts', 0)}")
    if m.get("pf_banned"): chk("banned", False, "RED", "pump.fun: is_banned")
    reds = [x["key"] for x in checks if x["status"] == "RED"]
    hard = [k for k in reds if k in p["hard"]]
    verdict = "FAIL" if hard else "PASS"
    return {"profile": profile, "checks": checks, "verdict": verdict, "hard_fails": hard, "reds": reds, "yellows": [x["key"] for x in checks if x["status"] == "YELLOW"]}

def age_str(h):
    return "?" if h is None else (f"{h/24:.0f}д" if h > 72 else f"{h:.1f}ч")

def render(m, ev):
    L = [f"=== memecoin-dd · этап 1 · {m.get('symbol') or '?'} ({m.get('name') or '?'}) · {m['chain']} ===",
         f"CA: {m['address']}", f"профиль: {ev['profile']} · dex: {','.join(m.get('dex_ids') or ['?'])} · возраст пары: {age_str(m.get('age_h'))} · источники: {', '.join(m['sources']) or 'НЕТ ДАННЫХ'}"]
    if m.get("pf_created_h"): L.append(f"pump.fun: создан {m['pf_created_h']:.1f}ч назад · complete={m.get('pf_complete')} · replies {m.get('pf_replies')} · ATH mcap ${f(m.get('pf_ath_mcap')):,.0f}")
    chg = m.get("chg") or {}
    L.append(f"Рынок: mcap ${f(m.get('mcap')):,.0f} · ликв ${f(m.get('liq_usd')):,.0f} · vol24 ${f(m.get('vol24')):,.0f} · vol1h ${f(m.get('vol1h')):,.0f} · txns24 {m.get('txns24', 0)} (buys {m.get('buys24', 0)}/sells {m.get('sells24', 0)}) · Δ1h {chg.get('h1')}% · Δ6h {chg.get('h6')}% · Δ24h {chg.get('h24')}%")
    if m.get("creator"): L.append(f"Дев: {m['creator']}" + (f" · RugCheck score {m.get('rug_score')}" if m.get("rug_score") is not None else "") + (f" · launchpad {m['launchpad']}" if m.get("launchpad") else ""))
    if m.get("risks"): L.append("Риски по API: " + "; ".join(map(str, m["risks"])))
    L.append("Соцсети: " + (" · ".join(f"{k}: {v}" for k, v in m["socials"].items() if v) or "нет"))
    L.append("--- Проверки ---")
    for c in ev["checks"]: L.append(f"{c['status']:<7}{c['key']:<16}{c['text']}")
    if ev["verdict"] == "FAIL": L.append(f"=== ВЕРДИКТ ЭТАПА 1: FAIL ({', '.join(ev['hard_fails'])}) — дальше не идём ===")
    else:
        L.append(f"=== ВЕРДИКТ ЭТАПА 1: PASS · красных: {len(ev['reds'])} ({', '.join(ev['reds']) or '—'}) · жёлтых: {len(ev['yellows'])} ({', '.join(ev['yellows']) or '—'}) ===")
        L.append("→ этап 2 (люди): дев-кошелёк и его история · снайперы/бандлы · KOL-холдеры и кто уже вышел · X по CA и тикеру · Telegram · нарратив. Маршруты: references/people-playbook.md")
    return "\n".join(L)

def main(a):
    t = load_thresholds()
    prof = a[a.index("--profile") + 1] if "--profile" in a else "auto"
    if "--offline" in a:
        d = a[a.index("--offline") + 1]
        raw = json.load(open(d if d.endswith(".json") else os.path.join(d, "raw.json")))
    else:
        chain, addr = a[0].lower(), a[1]
        if chain not in CHAINS: sys.exit(f"chain должен быть одним из: {', '.join(CHAINS)}")
        raw = fetch_all(chain, addr)
        if "--save" in a:
            d = a[a.index("--save") + 1]; os.makedirs(d, exist_ok=True); json.dump(raw, open(os.path.join(d, "raw.json"), "w"), ensure_ascii=False)
    m = extract(raw)
    if prof == "auto": prof = detect_profile(m, t)
    ev = evaluate(m, prof, t)
    print(json.dumps({"metrics": m, "eval": ev}, ensure_ascii=False, indent=1) if "--json" in a else render(m, ev))
    errs = {k: v["_err"] for k, v in raw.items() if isinstance(v, dict) and "_err" in v}
    if errs: print("ошибки источников:", errs, file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"): sys.exit(__doc__)
    main(sys.argv[1:])
