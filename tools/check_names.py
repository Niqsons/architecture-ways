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

Запуск:
    python tools/check_names.py            # staged-файлы (для hook)
    python tools/check_names.py ФАЙЛ...    # явные файлы, до коммита
    python tools/check_names.py --all      # всё, что под git
    python tools/check_names.py --history  # каждый блоб всей истории

Незнакомый аргумент — ошибка, а не молчаливый staged-режим: гейт,
проглотивший аргумент, отвечает не на тот вопрос, который ему задали.
"""
import os
import re
import subprocess
import sys

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

BLOCKING = {"имя продукта", "внешний адрес", "похоже на секрет"}

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".ico",
              ".woff", ".woff2", ".ttf", ".xlsx", ".docx", ".pyc"}


def load_forbidden():
    """Шаблоны имён из файла вне репозитория. Нет файла — отказ."""
    if not os.path.isfile(NAMES_FILE):
        print(f"[СТОП] нет файла со списком имён: {NAMES_FILE}")
        print("       Гейт не может подтвердить чистоту без него.")
        print("       Пустая проверка опаснее отсутствующей.")
        sys.exit(2)
    pats = []
    with open(NAMES_FILE, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.split("#", 1)[0].strip()
            if line:
                pats.append(re.compile(line, re.I))
    if not pats:
        print(f"[СТОП] файл {NAMES_FILE} не содержит ни одного шаблона.")
        sys.exit(2)
    return pats


def git(repo, *args):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True)
    return r.stdout.decode("utf-8", "replace")


def check_text(text, forbidden, hosts=None):
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
    args = ap.parse_args()

    repo = os.getcwd()
    if args.history:
        return check_history(repo)
    if args.files and args.all:
        ap.error("либо явные файлы, либо --all — не разом")

    mode = "all" if args.all else ("files" if args.files else "staged")

    forbidden = load_forbidden()
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
        for lineno, kind, what in check_text(text, forbidden, hosts):
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
    forbidden = load_forbidden()
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
        hits = [h for h in check_text(text, forbidden, hosts)
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
