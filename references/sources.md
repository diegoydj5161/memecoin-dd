# Источники данных: API, схема raw.json, коннекторы

## Публичные API без ключей (их вызывает `scripts/screen.py`)

| источник | URL | что даёт | лимиты |
|---|---|---|---|
| DexScreener pairs | `https://api.dexscreener.com/tokens/v1/<chain>/<CA>` | все пары токена: liquidity.usd, marketCap/fdv, volume h1/h6/h24, txns buys/sells, priceChange, pairCreatedAt, dexId, info.socials/websites, boosts | ~300 req/мин |
| DexScreener orders | `https://api.dexscreener.com/orders/v1/<chain>/<CA>` | оплаченные заказы: tokenProfile / communityTakeover (CTO) / tokenAd; status approved = «DEX paid» | ~60 req/мин |
| DexScreener trending/boosts | `https://api.dexscreener.com/token-boosts/latest/v1` · `/token-boosts/top/v1` · `/token-profiles/latest/v1` | что сейчас продвигают — источник кандидатов и оценка меты | ~60 req/мин |
| RugCheck (Solana) | `https://api.rugcheck.xyz/v1/tokens/<CA>/report` (полный) · `.../report/summary` (кратко: score, risks, lpLockedPct) | mintAuthority/freezeAuthority, tokenMeta.mutable, transferFee, topHolders (pct, insider, owner), knownAccounts (тип AMM/CREATOR), insiderNetworks, graphInsidersDetected, totalHolders, lockers, markets (lp), creator, creatorTokens, launchpad, risks, rugged | без ключа |
| GoPlus Solana | `https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses=<CA>` | mintable, freezable, closable, transfer_fee, holders, lp_holders, creators | без ключа |
| GoPlus EVM | `https://api.gopluslabs.io/api/v1/token_security/<chainId>?contract_addresses=<CA>` (1 eth · 56 bsc · 8453 base · 42161 arb) | is_honeypot, buy/sell_tax, is_mintable, is_proxy, is_open_source, owner_address, hidden_owner, can_take_back_ownership, transfer_pausable, is_blacklisted, trading_cooldown, holder_count, holders, lp_holders (is_locked), creator_address/percent, honeypot_with_same_creator | без ключа |
| honeypot.is (EVM) | `https://api.honeypot.is/v2/IsHoneypot?address=<CA>&chainID=<1|56|8453>` | симуляция покупки/продажи: isHoneypot, buyTax/sellTax, holderAnalysis (failed sells, siphoned), flags | 404 если пара не проиндексирована |
| pump.fun | `https://frontend-api-v3.pump.fun/coins/<CA>` | creator, created_timestamp, complete (мигрировал), usd_market_cap, ath_market_cap, reply_count, twitter/telegram/website, is_banned, verified | без ключа |

Проверено 2026-09-05: все отвечают из сэндбокса Higgsfield (перенос скрипта — `scripts/transfer_chunks.py`, см. SKILL.md §0). Из локального bash claude.ai — нет (белый список доменов).

## Схема `raw.json` для `screen.py --offline`

```json
{"chain": "solana", "address": "<CA>",
 "dex": <ответ tokens/v1 — список пар>,
 "orders": <ответ orders/v1>,
 "rugcheck": <report (полный) или {}>,
 "rugcheck_summary": <report/summary>,
 "goplus": <объект result[<CA>] из GoPlus>,
 "honeypot": <ответ honeypot.is (EVM)>,
 "pumpfun": <ответ pump.fun coins (solana, опционально)>}
```
Любой ключ можно опустить — соответствующие проверки станут `NA`. Через Chrome: открыть URL вкладкой → `get_page_text` → вставить JSON. Для Solana без полного report: положить summary в `rugcheck_summary` и GoPlus в `goplus` — холдеры и authorities возьмутся из GoPlus.

## Журнал (Notion)

Страница «Memecoin DD» → база «Журнал DD»: data_source `collection://1fea51dc-d299-4531-8d0d-ccacc3ec3cb0`, database `https://app.notion.com/p/8aa3221d81df40799e2f871dd0d18738`, views «Журнал» (все) и «Активные» (ждёт этап 2 / вердикт / в позиции). Схема полей — `assets/verdict-template.md`.

## Ручные UI (если API молчит)

RugCheck `rugcheck.xyz/tokens/<CA>` · GoPlus `gopluslabs.io/token-security/<chainId>/<CA>` · honeypot.is `honeypot.is/<ethereum|base|bsc>?address=<CA>` · gmgn (см. playbook) · DexScreener страница токена (уникальные мейкеры, «DEX paid» галочка, boosts).

## Коннекторы и ключи (опционально, ускоряют этап 2)

| что | зачем | как подключить |
|---|---|---|
| **CabalSpy MCP** — `https://mcp.cabalspy.xyz/mcp?api_key=<key>` | KOL/smart-money/whale кошельки на Solana, Base, BSC, ETH; «кто купил», кто держит/вышел, `detect_bundles`, `lookup_wallet` | ключ: apidashboard.cabalspy.xyz (1000 запросов бесплатно); в claude.ai — кастомный коннектор по URL с ключом в query (заголовки веб-коннектор не передаёт) |
| **Elfa AI** — скилл `elfa-ai/claude-ai-trading-skill` или их API | упоминания CA/тикера в X и Telegram, smart followers аккаунта, тренды | ключ: go.elfa.ai/claude-skills (1000 кредитов бесплатно) |
| **X API v2 bearer** (free tier) | поиск твитов и профили без браузера — для Claude Code/Hermes | developer.x.com → app → Bearer Token → `X_BEARER_TOKEN` |
| **token-xray MCP** (локальный, `npx -y token-xray`) | GoPlus + DexScreener одной командой (дубль этапа 1) для Claude Desktop/Code | конфиг mcpServers |
| **pumpfun-cli** (`ardha27/pumpfun-agent-skill`) | trending/new/graduating pump.fun из терминала, Hermes-совместимо | `uv tool install git+https://github.com/chainstacklabs/pumpfun-cli.git` |

Без ключей этап 2 полностью проходится браузером — дольше, но не хуже по данным: gmgn и Bubblemaps показывают то же, что CabalSpy, только без API.
