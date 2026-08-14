#!/usr/bin/env python3
"""Гейт: продуктовые имена, внутренние адреса и секреты не уезжают в git.

ЗАЧЕМ ОН ЕСТЬ. Правило «не публиковать продуктовые имена» держалось
текстом в CLAUDE.md — и не сработало. Проверка 2026-08-07 нашла
936 вхождений в 43 файлах и внутренний адрес шлюза в истории двух
репозиториев. Текст правила читают не всегда; гейт читает всегда.

ПОЧЕМУ СПИСОК ИМЁН НЕ ЗДЕСЬ. Список запрещённых имён сам является
тем, что запрещено: публичный architecture-ways/CLAUDE.md перечислял
их в тексте правила и тем публиковал. Поэтому имена лежат в
`~/.claude/projects/forbidden-names.txt`, вне всех репозиториев,
а здесь — только проверки, не требующие секретов.

ОТСУТСТВИЕ СПИСКА — ОТКАЗ, А НЕ УСПЕХ. Гейт без файла имён падает
с кодом 2. Пустая проверка, отрапортовавшая «чисто», опаснее
отсутствующей: она создаёт уверенность.

ИМЯ В ПОЗИЦИИ ХОСТА — ОТДЕЛЬНЫЙ КЛАСС. Часть внутренних зон названа
обычными словами, встречающимися в любой документации о развёртывании.
Списком подстрок такие не закрыть: гейт, краснеющий на каждом таком
слове, отключают целиком, а не чинят. Поэтому строка вида
`zone: <фрагмент>` в файле имён проверяется не «где угодно в тексте»,
а только внутри доменного имени: `zonex-app.internal` — находка,
то же слово в прозе — нет. Класс заведён 2026-08-14.

ПРИМЕРЫ ЗДЕСЬ ПОДСТАВНЫЕ, И ЭТО НЕ ПЕДАНТИЗМ. Первая редакция этого
абзаца поясняла правило на живом фрагменте — и гейт остановил
собственный коммит: файл, объясняющий, как прятать имена, публиковал
имя. Поэтому во всех примерах кода и тестов стоит `zonex`.

ЧЕГО ЭТОТ КЛАСС НЕ ЛОВИТ, И ЭТО НЕ ЧИНИТСЯ. Неоднозначный фрагмент,
названный в прозе — перечнем зон в тексте руководства, — автоматически
неотличим от обычного слова ни одним правилом. Такие находит вычитка
глазами. Гейт закрывает адресную форму, не словарную, и обещать
большее ему нельзя.

Запуск:
    python tools/check_names.py            # staged-файлы (для hook)
    python tools/check_names.py ФАЙЛ...    # явные файлы, до коммита
    python tools/check_names.py --all      # всё, что под git
    python tools/check_names.py --history  # каждый блоб всей истории
    python tools/check_names.py --selftest # проверки на своих образцах

Незнакомый аргумент — ошибка, а не молчаливый staged-режим: гейт,
проглотивший аргумент, отвечает не на тот вопрос, который ему задали.
"""
import os
import re
import subprocess
import sys

# Через hasattr, а не напрямую: под подменённым выводом (мутационная
# оснастка, перехват в тестах) у потока метода нет, и модуль переставал
# импортироваться. Гейт, который нельзя выполнить из проверки, проверкой
# не покрывается.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

NAMES_FILE = os.path.expanduser(
    r"~\.claude\projects\forbidden-names.txt")

# --- структурные проверки: секретов не требуют, живут в коде ---------

# Хосты, которым уезжать можно. Всё остальное в URL — подозрение:
# белый список ошибается в сторону лишнего вопроса, чёрный —
# в сторону пропуска.
HOST_ALLOW = {
    "localhost", "127.0.0.1", "0.0.0.0", "example.com", "example.ru",
    "example.org", "github.com", "raw.githubusercontent.com",
    "ollama.com", "api.anthropic.com", "pypi.org", "python.org",
    "docs.python.org", "www.w3.org", "www.omg.org",
    "graphml.graphdrawing.org", "www.gexf.net", "schema.org",
    "json-schema.org", "spdx.org", "creativecommons.org",
}

RE_URL = re.compile(r"https?://([A-Za-z0-9._-]+)")

# Домены документации по RFC 2606 — заведомо не существуют и потому
# не могут быть внутренним адресом.
RE_DOC_HOST = re.compile(r"(?i)(^|\.)(example\.(com|ru|org|net)|test|invalid|localhost)$")

# Хосты, разрешённые в этом репозитории. Лежат в файле, а не в коде:
# публичный адрес не секрет, и список растёт от репозитория
# к репозиторию — библиография исследования не то же, что зависимости
# сборки. Отличить публичный адрес от внутреннего машинно нельзя
# (`insiderllm.com` от `gateway.company.com`), поэтому разрешение
# всегда явное и вносится руками.
HOSTS_FILE = os.path.join("tools", "allowed-hosts.txt")


def load_hosts():
    hosts = set(HOST_ALLOW)
    if os.path.isfile(HOSTS_FILE):
        with open(HOSTS_FILE, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.split("#", 1)[0].strip().lower()
                if line:
                    hosts.add(line)
    return hosts

# Абсолютные пути. Свои рабочие каталоги разрешены: они не секрет
# и стоят в конфигах и .gitignore осмысленно.
RE_ABS_WIN = re.compile(r"\b[A-Za-z]:[\\/][^\s\"'<>|]{2,}")
RE_ABS_UNC = re.compile(r"\\\\[A-Za-z0-9._-]+\\[^\s\"'<>|]+")
RE_ABS_NIX = re.compile(r"(?<![\w.])/(?:home|opt|srv|mnt|var/www|Users)/[^\s\"'<>|:]+")
PATH_ALLOW = re.compile(
    r"(?i)^[A-Za-z]:[\\/](?:_archive|substrate-building|skills-factory"
    r"|skills-store|temporary-knowledge|architecture-ways"
    r"|путь|<)")

# Секреты: присвоение непустого значения ключу, похожему на секрет.
#
# Угловые скобки исключены из значения намеренно. Без них разметка,
# приклеенная к короткому значению, добирала ему длину до порога:
# `X-Session-Token: abc123</font>` в диаграмме давало значение из
# тринадцати знаков там, где настоящих знаков шесть. Секрет угловой
# скобки не содержит, а тег рядом с ним — обычное дело в документах.
RE_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|apikey|secret|password|passwd|token|bearer)"
    r"\s*[=:]\s*[\"']?([^\s\"'#,}<>]{8,})")
SECRET_PLACEHOLDER = re.compile(
    r"(?i)^(none|null|true|false|\$|<|\{|%|xxx+|\.\.\.|your|placeholder"
    r"|from-env|from-file|env\.|os\.environ|getenv|\*+)")

# Значение — выражение языка, а не литерал секрета: `token=cfg.get(...)`,
# `token=self._token`, `Bearer {key}`. Без этого гейт ловил три места,
# где `token` — имя параметра функции.
RE_SECRET_EXPR = re.compile(
    r"(?i)^(?:[A-Za-z_][\w.]*\s*[(\[]"          # вызов или индексация
    r"|[A-Za-z_]\w*\.\w+"                        # обращение к атрибуту
    r"|self\b|cfg\b|config\b|args\b|opts\b|kwargs\b"
    r"|f?[\"']?\{)")                             # подстановка в шаблон

# Явное подавление одной строки. Нужно, потому что подставные адреса
# и ключи в тестах — это и есть материал теста: проверка, которая
# ругается на собственный эталон, будет отключена целиком, а не
# исправлена. Пометка видна глазами и грепается.
GATE_OK = re.compile(r"gate-ok")

# --- имя в позиции хоста ---------------------------------------------
#
# Токен из меток через точку: `zonex-app.internal`, `example.com`,
# `1.17.11`, `patterns.md`. Дальше отсеиваются имена файлов, а среди
# оставшихся ищется фрагмент зоны. Одной большой регуляркой на все
# фрагменты это не делается: фрагменты — секрет, а регулярка живёт
# в публичном коде.
RE_HOSTLIKE = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+(?![\w-])")

# Последняя метка такая — значит это имя файла, а не хост. Без этого
# `zonex.md` в отчёте выглядел бы внутренним адресом.
NOT_HOST_TAIL = {
    "md", "markdown", "rst", "txt", "py", "sh", "ps1", "bat", "sql",
    "json", "json5", "yaml", "yml", "toml", "ini", "cfg", "conf",
    "xml", "csv", "html", "css", "js", "ts", "tsx", "jsx", "png",
    "jpg", "jpeg", "svg", "gif", "pdf", "zip", "log", "lock", "env",
    "template", "tpl", "j2", "bak", "orig", "jsonl",
}
# `example` в этот список не входит намеренно: `.example` — и суффикс
# файла-образца, и зарезервированный домен по RFC 2606, то есть ровно
# та форма, в которую обезличивают внутренние хосты. Отсев по нему
# погасил бы `zone01.corp.example` — нашла самопроверка.


def zone_hits(line, zones, hosts=()):
    """Фрагменты зон, стоящие внутри доменного имени.

    Фрагмент обязан быть отдельным куском метки: границей метки,
    дефисом или цифрой с обеих сторон. Иначе `zonexation.example.com`
    краснел бы из-за `zonex`, и класс перестали бы читать.

    Разрешённые хосты репозитория пропускаются: у приватных
    репозиториев бывают собственные имена в форме хоста — имя корпуса,
    имя стенда, — и запрет на них верен для публичного репозитория
    и неверен для приватного. Различие живёт в `tools/allowed-hosts.txt`,
    рядом с материалом, а не в коде гейта: код обязан быть одним
    на все копии.
    """
    out = []
    if not zones:
        return out
    for tok in RE_HOSTLIKE.findall(line):
        low = tok.lower()
        if low in hosts:
            continue
        labels = low.split(".")
        if labels[-1] in NOT_HOST_TAIL:
            continue
        for label in labels:
            for frag in zones:
                if re.search(r"(?:^|[-0-9])" + re.escape(frag)
                             + r"(?:$|[-0-9])", label):
                    out.append(tok)
                    break
            else:
                continue
            break
    return out


BLOCKING = {"имя продукта", "внешний адрес", "похоже на секрет",
            "внутренняя зона"}

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".ico",
              ".woff", ".woff2", ".ttf", ".xlsx", ".docx", ".pyc"}


def load_forbidden():
    """Шаблоны имён из файла вне репозитория. Нет файла — отказ.

    Возвращает пару: шаблоны для поиска где угодно и фрагменты зон,
    которые ищутся только в позиции доменного имени. Второй список
    задаётся строками `zone: <фрагмент>` — фрагмент литеральный,
    не регулярка: зоны пишут не для того, чтобы упражняться в синтаксисе.
    """
    if not os.path.isfile(NAMES_FILE):
        print(f"[СТОП] нет файла со списком имён: {NAMES_FILE}")
        print("       Гейт не может подтвердить чистоту без него.")
        print("       Пустая проверка опаснее отсутствующей.")
        sys.exit(2)
    pats, zones = [], []
    with open(NAMES_FILE, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.lower().startswith("zone:"):
                frag = line.split(":", 1)[1].strip().lower()
                if frag:
                    zones.append(frag)
            else:
                pats.append(re.compile(line, re.I))
    if not pats and not zones:
        print(f"[СТОП] файл {NAMES_FILE} не содержит ни одного шаблона.")
        sys.exit(2)
    return pats, zones


def git(repo, *args):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True)
    return r.stdout.decode("utf-8", "replace")


def check_text(text, forbidden, hosts=None, zones=()):
    """Возвращает список (номер строки, класс, что нашлось).

    Классы из BLOCKING останавливают коммит, остальные печатаются
    как замечание. Абсолютный путь к файлу сам по себе не утечка:
    `D:\\projects\\...` в примере команды — не адрес контура. Утечкой
    его делает продуктовое имя внутри, а это ловит первый слой.
    Блокировать по пути значило бы блокировать документацию.
    """
    if hosts is None:
        hosts = HOST_ALLOW
    out = []
    for i, line in enumerate(text.split("\n"), 1):
        if GATE_OK.search(line):
            continue
        for rx in forbidden:
            m = rx.search(line)
            if m:
                out.append((i, "имя продукта", m.group(0)))
        for tok in zone_hits(line, zones, hosts):
            out.append((i, "внутренняя зона", tok[:60]))
        for host in RE_URL.findall(line):
            host = host.rstrip(".,;:)]}")
            if (host.lower() not in hosts and not host.startswith("<")
                    and not RE_DOC_HOST.search(host.lower())):
                out.append((i, "внешний адрес", host))
        for rx in (RE_ABS_WIN, RE_ABS_UNC, RE_ABS_NIX):
            for m in rx.finditer(line):
                if not PATH_ALLOW.match(m.group(0)):
                    out.append((i, "абсолютный путь", m.group(0)[:60]))
        m = RE_SECRET.search(line)
        if (m and not SECRET_PLACEHOLDER.match(m.group(2))
                and not RE_SECRET_EXPR.match(m.group(2))):
            out.append((i, "похоже на секрет", f"{m.group(1)}=***"))
    return out


def files_to_check(repo, mode):
    if mode == "staged":
        names = git(repo, "diff", "--cached", "--name-only",
                    "--diff-filter=ACM").split("\n")
    else:
        names = git(repo, "ls-files").split("\n")
    return [n for n in names if n.strip()]


def selftest():
    """Проверки класса «внутренняя зона» на своих образцах.

    Фрагменты здесь подставные (`zonex`): настоящие живут вне
    репозитория, и набор, требующий их, публиковал бы то, что
    сторожит. Проверка нужна, потому что правило держится на границах
    метки, а границы — ровно то место, где регулярка врёт молча.
    """
    Z = ["zonex"]
    cases = [
        ("app-zonex.internal лежит тут",        1, "дефис слева"),
        ("service.zonex отвечает",              1, "фрагмент — вся метка"),
        ("zonex01.corp.example недоступен",     1, "цифра справа"),
        ("web01zonex.internal отвечает",         1, "цифра слева"),
        ("https://zonex.example.com/x",         1, "хост в URL"),
        ("App-ZONEX.Internal",                  1, "регистр не важен"),
        ("слово zonex посреди прозы",           0, "не хост — не находка"),
        ("файл zonex.md в каталоге",            0, "имя файла, не хост"),
        ("zonexation.example.com",              0, "фрагмент слит с буквами"),
        ("версия 1.17.11 вышла",                0, "номер версии"),
        ("обычный host.example.com",            0, "фрагмента нет"),
    ]
    bad = 0
    for line, want, why in cases:
        got = len([h for h in check_text(line, [], zones=Z)
                   if h[1] == "внутренняя зона"])
        ok = got == want
        bad += not ok
        print(f"[{'ok' if ok else 'СБОЙ'}] {why}: ждали {want}, "
              f"получили {got}")

    # Класс обязан останавливать коммит: проверка, нашедшая находку
    # и пропустившая её дальше, хуже отсутствующей.
    if "внутренняя зона" not in BLOCKING:
        print("[СБОЙ] класс не блокирует коммит")
        bad += 1
    else:
        print("[ok] класс блокирует коммит")

    # Подавление строкой работает и здесь — иначе эталоны собственных
    # тестов нечем пометить.
    if check_text("app-zonex.internal  gate-ok", [], zones=Z):
        print("[СБОЙ] gate-ok не подавляет находку")
        bad += 1
    else:
        print("[ok] gate-ok подавляет находку")

    # Разрешение репозитория снимает находку: у приватного репозитория
    # бывает своё имя в форме хоста, и запрещать его там незачем.
    allowed = {"app-zonex.internal"}
    if check_text("app-zonex.internal", [], hosts=allowed, zones=Z):
        print("[СБОЙ] разрешённый хост всё равно находка")
        bad += 1
    elif not check_text("app-zonex.internal", [], hosts=set(), zones=Z):
        print("[СБОЙ] без разрешения находки тоже нет — проверка пустая")
        bad += 1
    else:
        print("[ok] разрешение хоста снимает находку, без него — находка")

    print(f"\n{'[!!] сбоев: ' + str(bad) if bad else '[ok] самопроверка чиста'}")
    return 1 if bad else 0


def main():
    # argparse, а не разбор sys.argv руками. Прежняя редакция глотала
    # незнакомые аргументы молча: `check_names.py <файл>` и даже
    # `--help` давали «[ok] чисто (staged)» — аргумент игнорировался,
    # проверялся пустой индекс. Пустая проверка, отрапортовавшая
    # «чисто», опаснее отсутствующей — предупреждение из шапки этого
    # же файла, которое он сам и нарушал. Найдено сквозным прогоном:
    # первая форма ушла в облако с такой «проверкой».
    import argparse
    ap = argparse.ArgumentParser(
        description="Гейт: продуктовые имена, адреса и секреты "
                    "не уезжают в git")
    ap.add_argument("files", nargs="*",
                    help="проверить эти файлы (до коммита, вне индекса)")
    ap.add_argument("--all", action="store_true",
                    help="всё, что под git")
    ap.add_argument("--history", action="store_true",
                    help="каждый блоб всей истории")
    ap.add_argument("--selftest", action="store_true",
                    help="проверки на своих образцах, файл имён не нужен")
    args = ap.parse_args()

    repo = os.getcwd()
    if args.selftest:
        return selftest()
    if args.history:
        return check_history(repo)
    if args.files and args.all:
        ap.error("либо явные файлы, либо --all — не разом")

    mode = "all" if args.all else ("files" if args.files else "staged")

    forbidden, zones = load_forbidden()
    hosts = load_hosts()
    bad = warn = 0
    if mode == "files":
        файлы = []
        for f in args.files:
            if not os.path.isfile(os.path.join(repo, f)):
                print(f"[!!] файла нет: {f}")
                return 2
            файлы.append(f)
    else:
        файлы = files_to_check(repo, mode)
    for rel in файлы:
        if os.path.splitext(rel)[1].lower() in BINARY_EXT:
            continue
        if any(p in SKIP_DIRS for p in rel.replace("\\", "/").split("/")):
            continue
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as fh:
            raw = fh.read()
        if b"\x00" in raw[:8000]:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for lineno, kind, what in check_text(text, forbidden, hosts,
                                             zones):
            mark = "!!" if kind in BLOCKING else "  "
            print(f"[{mark}] {rel}:{lineno}: [{kind}] {what}")
            if kind in BLOCKING:
                bad += 1
            else:
                warn += 1

    if warn:
        print(f"\n[..] замечаний (не блокируют): {warn}")
    if bad:
        print(f"\n[!!] находок: {bad}. Коммит остановлен.")
        print("     Обезличить, вынести материал в X:\\_archive,")
        print("     либо пометить строку `gate-ok`, если это эталон теста.")
        return 1
    print(f"[ok] чисто ({mode})")
    return 0


def check_history(repo):
    """Тот же контроль по каждому блобу истории.

    Рабочее дерево может быть чистым, а старый коммит — нет: на GitHub
    он остаётся достижимым по SHA. Так и нашёлся адрес шлюза, которого
    в HEAD одного из репозиториев уже не было.
    """
    forbidden, zones = load_forbidden()
    hosts = load_hosts()
    names = {}
    for line in git(repo, "rev-list", "--objects", "--all").split("\n"):
        p = line.split(" ", 1)
        if len(p) == 2:
            names.setdefault(p[0], p[1])

    proc = subprocess.Popen(
        ["git", "-C", repo, "cat-file", "--batch-all-objects", "--batch",
         "--buffer"], stdout=subprocess.PIPE)
    bad, seen = 0, set()
    out = proc.stdout
    while True:
        header = out.readline()
        if not header:
            break
        f = header.split()
        if len(f) < 3:
            continue
        sha, kind, size = f[0].decode(), f[1].decode(), int(f[2])
        data = out.read(size)
        out.read(1)
        if kind != "blob" or b"\x00" in data[:8000]:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # Только блокирующие классы: абсолютный путь в старом RUN.md
        # не повод объявлять историю грязной, иначе отчёт всегда красный
        # и его перестают читать.
        hits = [h for h in check_text(text, forbidden, hosts, zones)
                if h[1] in BLOCKING]
        if hits:
            where = names.get(sha, "<блоб без имени>")
            for lineno, cls, what in hits[:3]:
                key = (where, cls, what)
                if key in seen:
                    continue
                seen.add(key)
                print(f"{where}:{lineno}: [{cls}] {what}")
                bad += 1

    print(f"\n{'[!!] находок в истории: ' + str(bad) if bad else '[ok] история чиста'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
