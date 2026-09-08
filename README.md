# memecoin-dd

Скилл для Claude: due diligence мемкоинов «по людям». Этап 0 — scripts/discover.py (кандидаты $10k–$500k), этап 1 — scripts/screen.py (детерминированный фильтр), этап 2 — по SKILL.md и references/.

Сэндбокс тянет скрипты одной строкой:

curl -fsSL https://raw.githubusercontent.com/diegoydj5161/memecoin-dd/main/scripts/screen.py -o screen.py && curl -fsSL https://raw.githubusercontent.com/diegoydj5161/memecoin-dd/main/scripts/discover.py -o discover.py

Ветка main = рабочая версия; версия и история правок — в шапке SKILL.md и references/thresholds.md.
