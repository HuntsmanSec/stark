"""Command line interface: ``stark``."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __description__, __version__
from .config import DEFAULT_SETTINGS, Config, cache_dir, env_var_for, mask
from .models import Verdict
from .observables import ALL_TYPES, ObsType, iter_lines, parse_observable
from .output import FORMATS, render, use_color

BANNER = r"""
  ____    _____      _      ____    _  __
 / ___|  |_   _|    / \    |  _ \  | |/ /
 \___ \    | |     / _ \   | |_) | | ' /
  ___) |_  | | _  / ___ \ _|  _ < _| . \ _
 |____/(_) |_|(_)/_/   \_(_)_| \_(_)_|\_(_)
 Security Threat Assessment and Reputation Kit  v{v}
"""

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_FLAGGED = 0, 1, 2, 3


def _err(msg: str) -> None:
    print(f"stark: {msg}", file=sys.stderr)


def _csv_list(values: Optional[List[str]]) -> List[str]:
    out: List[str] = []
    for v in values or []:
        out += [x.strip() for x in v.split(",") if x.strip()]
    return out


def _parse_types(values) -> set:
    names = _csv_list(values)
    if not names:
        return set(ALL_TYPES)
    groups = {"ip": {ObsType.IPV4, ObsType.IPV6}, "hash": {ObsType.MD5, ObsType.SHA1, ObsType.SHA256}}
    out = set()
    for n in names:
        n = n.lower()
        out |= groups.get(n) or {ObsType(n)}
    return out


# ------------------------------------------------------------------ shared opts


def _add_query_opts(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("sources")
    g.add_argument("-p", "--providers", action="append", metavar="LIST",
                   help="only these providers (comma separated; e.g. vt,abuseipdb,otx)")
    g.add_argument("-x", "--exclude", action="append", metavar="LIST", help="skip these providers")
    g.add_argument("--all", action="store_true", help="also run informational sources (ipinfo, crt.sh)")
    g.add_argument("--no-cache", action="store_true", help="ignore and do not write the local result cache")
    g.add_argument("--timeout", type=float, help="per-request timeout in seconds")
    g.add_argument("--workers", type=int, help="concurrent lookups per provider without rate limit")


def _add_output_opts(p: argparse.ArgumentParser, default_fmt: str = "table") -> None:
    g = p.add_argument_group("output")
    g.add_argument("-F", "--format", choices=FORMATS, default=default_fmt, help=f"output format (default {default_fmt})")
    g.add_argument("-o", "--output", metavar="FILE", help="write to FILE instead of stdout")
    g.add_argument("--raw", action="store_true", help="include raw provider details in json/jsonl")
    g.add_argument("--tlp", default="clear", choices=["clear", "green", "amber", "red"],
                   help="TLP marking for STIX output (default clear)")
    g.add_argument("--stix-all", action="store_true",
                   help="STIX: create indicators for every observable, not only malicious/suspicious")
    g.add_argument("--stix", metavar="FILE", help="additionally write a STIX 2.1 bundle to FILE")
    g.add_argument("--fail-on", choices=["malicious", "suspicious"],
                   help=f"exit with code {EXIT_FLAGGED} if any observable reaches this verdict (CI/SOAR use)")
    g.add_argument("-v", "--verbose", action="store_true", help="per-source detail even for multiple observables")
    g.add_argument("--all-sources", action="store_true",
                   help="table: also show sources that errored or had no data (hidden by default)")
    g.add_argument("-q", "--quiet", action="store_true", help="no progress output on stderr")
    g.add_argument("--no-color", action="store_true", help="disable ANSI colours")


def _engine(args):
    from .engine import Stark

    try:
        return Stark(
            providers=_csv_list(args.providers) or None,
            exclude=_csv_list(args.exclude),
            include_informational=args.all,
            use_cache=not args.no_cache,
            timeout=args.timeout,
            workers=args.workers,
        )
    except KeyError as exc:
        _err(str(exc.args[0]))
        sys.exit(EXIT_USAGE)


def _progress(quiet: bool):
    if quiet or not sys.stderr.isatty():
        return None

    def fn(done, total, res):
        sys.stderr.write(f"\r  querying... {done}/{total}  ({res.provider}: {res.observable.value[:40]})"
                         + " " * 20)
        if done == total:
            sys.stderr.write("\r" + " " * 100 + "\r")
        sys.stderr.flush()

    return fn


def _run_and_emit(args, observables) -> int:
    if not observables:
        _err("no valid observables to query")
        return EXIT_USAGE
    engine = _engine(args)
    if not engine.providers:
        _err("no providers are available. Set API keys with 'stark config set <provider>' "
             "or run 'stark providers' to see which sources work without a key.")
        return EXIT_ERROR
    if not args.quiet:
        print(f"[*] {len(observables)} observable(s) x {len(engine.providers)} source(s)", file=sys.stderr)
    reports = engine.query_many(observables, progress=_progress(args.quiet))
    _emit(args, reports)
    return _exit_code(args, reports)


def _emit(args, reports) -> None:
    color = not args.no_color and not args.output and use_color()
    text = render(args.format, reports, color=color, include_raw=args.raw, verbose=args.verbose,
                  all_indicators=args.stix_all, tlp=args.tlp, all_sources=args.all_sources)
    if args.output:
        Path(args.output).write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        if not args.quiet:
            print(f"[+] wrote {args.format} output to {args.output}", file=sys.stderr)
    else:
        _safe_print(text)
    if args.stix:
        Path(args.stix).write_text(render("stix", reports, all_indicators=args.stix_all, tlp=args.tlp),
                                   encoding="utf-8")
        if not args.quiet:
            print(f"[+] wrote STIX 2.1 bundle to {args.stix}", file=sys.stderr)


def _safe_print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:  # legacy Windows code pages
        sys.stdout.write(text.encode(sys.stdout.encoding or "ascii", "replace").decode(
            sys.stdout.encoding or "ascii") + "\n")


def _exit_code(args, reports) -> int:
    if args.fail_on:
        threshold = Verdict(args.fail_on).rank
        if any(r.verdict.rank >= threshold and r.verdict is not Verdict.ERROR for r in reports):
            return EXIT_FLAGGED
    return EXIT_OK


# --------------------------------------------------------------------- commands


def cmd_query(args) -> int:
    from .stix import load_bundle

    forced = ObsType(args.type) if args.type else None
    obs = []
    bad = []
    for raw in args.observables:
        o = parse_observable(raw, forced=forced)
        (obs.append(o) if o else bad.append(raw))
    for f in args.file or []:
        if f == "-":
            obs += list(iter_lines(sys.stdin, forced=forced))
        else:
            with open(f, "r", encoding="utf-8-sig", errors="replace") as fh:
                obs += list(iter_lines(fh, forced=forced))
    for b in args.stix_in or []:
        obs += load_bundle(b)
    if not args.observables and not args.file and not args.stix_in and not sys.stdin.isatty():
        obs += list(iter_lines(sys.stdin, forced=forced))
    for b in bad:
        _err(f"skipping '{b}': not a recognised IP, domain, URL, hash or email (use --type to force)")
    uniq = list(dict.fromkeys(obs))
    if args.types:
        wanted = _parse_types(args.types)
        uniq = [o for o in uniq if o.type in wanted]
    return _run_and_emit(args, uniq)


def cmd_enrich(args) -> int:
    from .integrations import PRESETS, resolve_columns
    from .integrations.timeline import extract_rows, read_table, write_enriched

    preset = PRESETS[args.preset]
    table = read_table(args.input)
    columns = _csv_list(args.columns) or resolve_columns(preset, table.columns)
    per_row, unique = extract_rows(table, columns=columns, skip=preset.skip,
                                   types=_parse_types(args.types), include_private=args.include_private)
    if not args.quiet:
        print(f"[*] {args.input}: {len(table.rows)} row(s), {len(unique)} unique observable(s) "
              f"(preset {preset.name})", file=sys.stderr)
    if args.max and len(unique) > args.max:
        _err(f"{len(unique)} observables exceeds --max {args.max}; narrow with --types/--columns or raise --max")
        return EXIT_USAGE
    if args.dry_run:
        for o in unique:
            print(f"{o.type.value}\t{o.value}")
        return EXIT_OK
    if not unique:
        _err("no observables found")
        return EXIT_OK
    engine = _engine(args)
    if not engine.providers:
        _err("no providers are available; configure API keys first")
        return EXIT_ERROR
    reports = engine.query_many(unique, progress=_progress(args.quiet))
    out = args.enriched or _default_enriched_name(args.input)
    n = write_enriched(table, per_row, reports, out, only_flagged=args.only_flagged)
    if not args.quiet:
        print(f"[+] wrote {n} enriched row(s) to {out}", file=sys.stderr)
    _emit(args, reports)
    return _exit_code(args, reports)


def _default_enriched_name(path: str) -> str:
    p = Path(path)
    return str(p.with_name(p.stem + ".stark" + (p.suffix or ".csv")))


def cmd_extract(args) -> int:
    from .integrations.timeline import extract_rows, read_table
    from .observables import extract

    types = _parse_types(args.types)
    found = []
    for f in args.files:
        if Path(f).suffix.lower() in (".csv", ".tsv", ".json", ".jsonl", ".ndjson"):
            _, uniq = extract_rows(read_table(f), types=types, include_private=args.include_private)
            found += uniq
        else:
            text = sys.stdin.read() if f == "-" else Path(f).read_text(encoding="utf-8-sig", errors="replace")
            found += list(extract(text, types=types, include_private=args.include_private))
    found = list(dict.fromkeys(found))
    if args.format == "json":
        _safe_print(json.dumps([o.to_dict() for o in found], indent=2))
    elif args.format == "csv":
        print("ioc_value,ioc_type")
        for o in found:
            print(f"\"{o.value}\",{o.type.value}")
    else:
        for o in found:
            print(o.defanged if args.defang else o.value)
    return EXIT_OK


def cmd_providers(args) -> int:
    from .providers import PROVIDERS

    cfg = Config()
    rows = []
    for p in PROVIDERS:
        src = cfg.key_source(p.config_key())
        status = "ready" if src else ("ready (no key)" if not p.requires_key else "needs key")
        if p.name in cfg.disabled:
            status = "disabled"
        rows.append({
            "name": p.name, "display": p.display, "types": sorted(t.value for t in p.supported),
            "key": p.config_key(), "key_required": p.requires_key, "key_source": src, "status": status,
            "informational": p.informational, "rate_limit_per_min": p.rate_limit, "homepage": p.homepage,
            "description": p.description,
        })
    if args.json:
        print(json.dumps(rows, indent=2))
        return EXIT_OK
    color = use_color()
    w = max(len(r["name"]) for r in rows)
    print(f"{'PROVIDER'.ljust(w)}  {'STATUS'.ljust(15)}  {'KEY NAME'.ljust(15)}  TYPES")
    for r in rows:
        st = r["status"].ljust(15)
        if color:
            c = "\033[32m" if r["status"].startswith("ready") else ("\033[90m" if r["status"] == "disabled" else "\033[33m")
            st = f"{c}{st}\033[0m"
        info = " (info)" if r["informational"] else ""
        print(f"{r['name'].ljust(w)}  {st}  {r['key'].ljust(15)}  {','.join(r['types'])}{info}")
    print(f"\nSet a key:  stark config set <key name>     (or env var {env_var_for('<key name>')})")
    return EXIT_OK


def cmd_config(args) -> int:
    from .providers import key_names

    cfg = Config()
    action = args.action
    if action == "path":
        print(cfg.path)
        return EXIT_OK
    if action == "show":
        print(f"# {cfg.path}{'' if cfg.path.exists() else ' (not created yet)'}")
        print("[keys]")
        for k in key_names():
            src = cfg.key_source(k)
            val = mask(cfg.get_key(k)) if src else "-"
            print(f"  {k.ljust(16)} {val}{f'  ({src})' if src else ''}")
        print("[settings]")
        for k, v in sorted(cfg.settings.items()):
            print(f"  {k.ljust(16)} {v}")
        print(f"[providers]\n  disabled         {', '.join(cfg.disabled) or '-'}")
        return EXIT_OK
    if action == "init":
        print(f"Interactive key setup - press Enter to keep the current value / skip.\nFile: {cfg.path}\n")
        for k in key_names():
            cur = cfg.keys.get(k)
            v = getpass.getpass(f"  {k}{f' [{mask(cur)}]' if cur else ''}: ").strip()
            if v:
                cfg.set_key(k, v)
        cfg.save()
        print(f"\n[+] saved {cfg.path}")
        return EXIT_OK
    if action == "set":
        if not args.name:
            _err("usage: stark config set <key name> [value]")
            return EXIT_USAGE
        name = args.name.lower()
        if name not in key_names():
            _err(f"unknown key '{name}'. Valid: {', '.join(key_names())}")
            return EXIT_USAGE
        value = args.value or getpass.getpass(f"{name} API key (input hidden): ").strip()
        if not value:
            _err("empty value; nothing saved")
            return EXIT_USAGE
        cfg.set_key(name, value)
        cfg.save()
        print(f"[+] {name} key saved to {cfg.path}")
        return EXIT_OK
    if action == "unset":
        if cfg.unset_key(args.name or ""):
            cfg.save()
            print(f"[+] removed {args.name}")
            return EXIT_OK
        _err(f"no stored key named '{args.name}'")
        return EXIT_ERROR
    if action == "setting":
        if not args.name or args.value is None or args.name not in DEFAULT_SETTINGS:
            _err(f"usage: stark config setting <name> <value>; names: {', '.join(DEFAULT_SETTINGS)}")
            return EXIT_USAGE
        default = DEFAULT_SETTINGS[args.name]
        val = args.value
        if isinstance(default, bool):
            val = val.lower() in ("1", "true", "yes", "on")
        elif isinstance(default, int):
            val = int(val)
        cfg.settings[args.name] = val
        cfg.save()
        print(f"[+] {args.name} = {val}")
        return EXIT_OK
    if action in ("disable", "enable"):
        from .providers import resolve

        try:
            name = resolve(args.name or "")
        except KeyError as exc:
            _err(str(exc.args[0]))
            return EXIT_USAGE
        if action == "disable" and name not in cfg.disabled:
            cfg.disabled.append(name)
        if action == "enable" and name in cfg.disabled:
            cfg.disabled.remove(name)
        cfg.save()
        print(f"[+] {name} {action}d")
        return EXIT_OK
    return EXIT_USAGE


def cmd_cache(args) -> int:
    from .cache import ResultCache

    path = cache_dir() / "results.sqlite"
    if args.action == "path":
        print(path)
        return EXIT_OK
    if not path.exists():
        print("cache is empty")
        return EXIT_OK
    c = ResultCache(path, 1)
    n = c.clear()
    c.close()
    print(f"[+] removed {n} cached result(s)")
    return EXIT_OK


def cmd_serve(args) -> int:
    try:
        from .web.app import serve
    except ImportError as exc:  # pragma: no cover
        _err(f"the workspace needs extra packages ({exc.name}). Install with: pip install 'stark-osint[web]'")
        return EXIT_ERROR
    serve(host=args.host, port=args.port, open_browser=not args.no_browser, allow_signup=not args.no_signup,
          db_path=args.db, secure_cookies=args.secure_cookies)
    return EXIT_OK


# ------------------------------------------------------------------------ parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="stark",
        description=f"S.T.A.R.K - {__description__}. Consolidated OSINT reputation lookups for IPs, domains, "
                    "URLs, file hashes and email addresses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  stark query 185.220.101.1\n"
               "  stark query evil[.]com hxxps://bad.example/x 44d88612fea8a8f36de82e1278abb02f\n"
               "  stark query -f iocs.txt -F csv -o results.csv --stix results.stix.json\n"
               "  stark query --stix-in feed.json -F irflow -o irflow_iocs.csv\n"
               "  stark enrich timeline.csv --preset hayabusa --only-flagged\n"
               "  stark config set virustotal\n",
    )
    p.add_argument("-V", "--version", action="version", version=f"stark {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    q = sub.add_parser("query", aliases=["q"], help="look up one or more observables",
                       description="Look up IPs, domains, URLs, hashes or emails. Defanged input is accepted.")
    q.add_argument("observables", nargs="*", help="observables to query (or pipe a list on stdin)")
    q.add_argument("-f", "--file", action="append", metavar="FILE", help="file with one observable per line ('-' = stdin)")
    q.add_argument("--stix-in", action="append", metavar="FILE", help="read observables from a STIX 2.x bundle")
    q.add_argument("-t", "--type", choices=[t.value for t in ObsType], help="force the observable type")
    q.add_argument("--types", action="append", metavar="LIST", help="only query these types (ip,domain,url,hash,email,...)")
    _add_query_opts(q)
    _add_output_opts(q)
    q.set_defaults(func=cmd_query)

    e = sub.add_parser("enrich", help="extract IOCs from a timeline (Hayabusa/IRFlow/VESTIGEX/CSV/JSON) and enrich it",
                       description="Extract observables from every row of a CSV/TSV/JSON/JSONL file, query them and "
                                   "write an enriched copy with STARK_* verdict columns.")
    e.add_argument("input", help="timeline / export file")
    e.add_argument("--preset", default="generic", choices=["generic", "hayabusa", "irflow", "vestigex"])
    e.add_argument("--columns", action="append", metavar="LIST", help="only mine these columns")
    e.add_argument("--types", action="append", metavar="LIST", help="observable types to extract")
    e.add_argument("--include-private", action="store_true", help="include private/reserved IP addresses")
    e.add_argument("--enriched", metavar="FILE", help="enriched output path (default <input>.stark.<ext>)")
    e.add_argument("--only-flagged", action="store_true", help="enriched file only keeps malicious/suspicious rows")
    e.add_argument("--max", type=int, default=500, help="refuse to query more than N observables (default 500, 0=no limit)")
    e.add_argument("--dry-run", action="store_true", help="only list the observables that would be queried")
    _add_query_opts(e)
    _add_output_opts(e)
    e.set_defaults(func=cmd_enrich)

    x = sub.add_parser("extract", help="extract (and refang) IOCs from text, logs, CSV or JSON without querying")
    x.add_argument("files", nargs="+", help="input files ('-' = stdin)")
    x.add_argument("--types", action="append", metavar="LIST")
    x.add_argument("--include-private", action="store_true")
    x.add_argument("--defang", action="store_true", help="print defanged values")
    x.add_argument("-F", "--format", choices=["txt", "csv", "json"], default="txt")
    x.set_defaults(func=cmd_extract)

    pr = sub.add_parser("providers", help="list reputation sources and whether they are configured")
    pr.add_argument("--json", action="store_true")
    pr.set_defaults(func=cmd_providers)

    c = sub.add_parser("config", help="manage API keys and settings",
                       description="Actions: path | show | init | set <key> [value] | unset <key> | "
                                   "setting <name> <value> | disable <provider> | enable <provider>")
    c.add_argument("action", choices=["path", "show", "init", "set", "unset", "setting", "disable", "enable"])
    c.add_argument("name", nargs="?")
    c.add_argument("value", nargs="?", help="omit to be prompted (keeps the key out of shell history)")
    c.set_defaults(func=cmd_config)

    ca = sub.add_parser("cache", help="manage the local result cache")
    ca.add_argument("action", choices=["clear", "path"])
    ca.set_defaults(func=cmd_cache)

    s = sub.add_parser("serve", aliases=["ui"], help="start the S.T.A.R.K workspace (web UI)",
                       description="Start the browser workspace. Running 'stark' with no arguments does the same.")
    s.add_argument("--host", default="127.0.0.1",
                   help="interface to listen on (default 127.0.0.1; use 0.0.0.0 to share with a team)")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--no-browser", action="store_true", help="don't open a browser window")
    s.add_argument("--no-signup", action="store_true", help="disable self sign-up after the first account")
    s.add_argument("--secure-cookies", action="store_true", help="mark cookies Secure (when served over HTTPS)")
    s.add_argument("--db", metavar="FILE", help="workspace database path (default: per-user data folder)")
    s.set_defaults(func=cmd_serve)

    v = sub.add_parser("version", help="print version")
    v.set_defaults(func=lambda a: print(BANNER.format(v=__version__)) or EXIT_OK)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        # No command: start the workspace UI (what a double-clicked binary should do).
        print(BANNER.format(v=__version__))
        args = parser.parse_args(["serve"])
    if getattr(args, "max", None) == 0:
        args.max = None
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        _err("interrupted")
        return 130
    except (OSError, ValueError) as exc:
        _err(str(exc))
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
