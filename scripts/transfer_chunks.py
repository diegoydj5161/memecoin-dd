#!/usr/bin/env python3
"""Печатает готовые команды для переноса screen.py (+ thresholds.json, если правился) в сэндбокс с интернетом
(например Higgsfield sandbox_exec из claude.ai) ПЛОСКИМ ТЕКСТОМ — base64/gzip при копировании моделью бьётся.

Порядок:
  0) в сэндбоксе (background:true):  mkdir -p /home/user/dd && nohup sleep 840 >/dev/null 2>&1 &   — лизинг 15 мин
  1) python3 transfer_chunks.py            → выводит N блоков; каждый блок целиком = одна команда sandbox_exec
  2) последний блок печатает md5sum — сверить с локальным, затем `python3 -m py_compile screen.py`
Split идёт по границам top-level `def`, куски ≤ 12 000 символов (v0.8 screen.py = 5 блоков; соседние блоки суммой ≤ 16 000 символов
можно склеить в один вызов sandbox_exec). ВАЖНО: сэндбокс сбрасывается, если вызов превысил timeout_seconds, — лизинг (`nohup sleep 840 &`)
только отдельным вызовом с background:true, прогоны токенов — тоже в фоне, опрос короткими вызовами.
"""
import hashlib, os, sys

LIMIT = 12000
here = os.path.dirname(os.path.abspath(__file__))
files = ["screen.py"] + (["thresholds.json"] if "--with-thresholds" in sys.argv else [])
for name in files:
    src = open(os.path.join(here, name), encoding="utf-8").read().rstrip("\n")
    md5 = hashlib.md5((src + "\n").encode("utf-8")).hexdigest()   # heredoc добавляет ровно один \n в конце
    # сегменты по границам top-level def, затем жадная упаковка в блоки ≤ LIMIT*0.9
    segs, cur = [], []
    for ln in src.split("\n"):
        if cur and ln.startswith("def "): segs.append("\n".join(cur)); cur = []
        cur.append(ln)
    if cur: segs.append("\n".join(cur))
    chunks, cur = [], ""
    for sg in segs:
        if cur and len(cur) + len(sg) + 1 > LIMIT * 0.9: chunks.append(cur); cur = sg
        else: cur = sg if not cur else cur + "\n" + sg
    if cur: chunks.append(cur)
    print(f"##### {name}: {len(chunks)} блок(ов), локальный md5 {md5}, {len(src)} символов\n")
    for i, ch in enumerate(chunks):
        op = ">" if i == 0 else ">>"
        tail = f"\ncd /home/user/dd && wc -c {name} && md5sum {name}" + (" && python3 -m py_compile screen.py && echo COMPILED" if name == "screen.py" and i == len(chunks) - 1 else "")
        print(f"----- блок {i + 1}/{len(chunks)} ({len(ch)} символов) — вставить как одну команду sandbox_exec -----")
        print(f"mkdir -p /home/user/dd && cat {op} /home/user/dd/{name} <<'XEOF'\n{ch}\nXEOF{tail}\n")
