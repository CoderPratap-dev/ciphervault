#!/usr/bin/env python3
"""
CipherVault CLI
Usage: python -m ciphervault [command] [options]
"""

import argparse
import getpass
import os
import secrets
import string
import sys
from pathlib import Path

# Allow running as script or module
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.vault.vault import Vault

DEFAULT_VAULT = Path.home() / ".ciphervault" / "default.cvlt"

CYAN    = "\033[96m"
MAGENTA = "\033[95m"
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
DIM     = "\033[2m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

BANNER = f"""
{CYAN}  ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗{RESET}
{CYAN} ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗{RESET}
{CYAN} ██║     ██║██████╔╝███████║█████╗  ██████╔╝{RESET}
{CYAN} ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗{RESET}
{CYAN} ╚██████╗██║██║     ██║  ██║███████╗██║  ██║{RESET}
{CYAN}  ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝{RESET}
{MAGENTA}  ╚═ VAULT ═╝  {DIM}AES-256-GCM · Zero-knowledge{RESET}
"""


def get_vault(args) -> Vault:
    path = Path(getattr(args, "vault", None) or DEFAULT_VAULT)
    path.parent.mkdir(parents=True, exist_ok=True)
    return Vault(str(path))


def prompt_password(prompt="Master password: ", confirm=False) -> str:
    pw = getpass.getpass(prompt)
    if confirm:
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            print(f"{RED}Passwords do not match.{RESET}")
            sys.exit(1)
    return pw


def generate_password(length=24, symbols=True) -> str:
    chars = string.ascii_letters + string.digits
    if symbols:
        chars += "!@#$%^&*()-_=+"
    return "".join(secrets.choice(chars) for _ in range(length))


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_init(args):
    v = get_vault(args)
    print(BANNER)
    print(f"{CYAN}  Creating new vault at:{RESET} {v.path}\n")
    pw = prompt_password("Set master password: ", confirm=True)
    v.init(pw)
    print(f"\n{GREEN}  ✓ Vault initialized successfully.{RESET}")
    print(f"{DIM}  Keep your master password safe — there is NO recovery.{RESET}\n")


def cmd_set(args):
    v = get_vault(args)
    pw = prompt_password()
    v.unlock(pw)

    value = args.value
    if not value:
        if args.generate:
            value = generate_password(args.length, not args.no_symbols)
            print(f"\n{CYAN}  Generated:{RESET} {BOLD}{value}{RESET}")
        else:
            value = getpass.getpass(f"Value for '{args.name}': ")

    tags = [t.strip() for t in args.tags.split(",")] if args.tags else []
    entry = v.set(args.name, value, tags=tags, note=args.note or "")

    print(f"\n{GREEN}  ✓ Secret '{entry.name}' saved.{RESET}")
    if tags:
        print(f"  Tags: {', '.join(tags)}")


def cmd_get(args):
    v = get_vault(args)
    pw = prompt_password()
    v.unlock(pw)

    entry = v.get(args.name)
    if not entry:
        print(f"{RED}  Secret '{args.name}' not found.{RESET}")
        sys.exit(1)

    if args.raw:
        print(entry.value, end="")
    else:
        print(f"\n  {CYAN}{BOLD}{entry.name}{RESET}")
        print(f"  {DIM}{'─' * 40}{RESET}")
        print(f"  {BOLD}Value:{RESET}   {entry.value}")
        if entry.note:
            print(f"  {BOLD}Note:{RESET}    {entry.note}")
        if entry.tags:
            print(f"  {BOLD}Tags:{RESET}    {', '.join(entry.tags)}")
        print(f"  {DIM}Updated: {_fmt_time(entry.updated_at)}{RESET}\n")


def cmd_delete(args):
    v = get_vault(args)
    pw = prompt_password()
    v.unlock(pw)

    confirm = input(f"  Delete '{args.name}'? [{YELLOW}y/N{RESET}]: ").strip().lower()
    if confirm != "y":
        print("  Aborted.")
        return

    if v.delete(args.name):
        print(f"{GREEN}  ✓ Deleted '{args.name}'.{RESET}")
    else:
        print(f"{RED}  Secret not found.{RESET}")
        sys.exit(1)


def cmd_list(args):
    v = get_vault(args)
    pw = prompt_password()
    v.unlock(pw)

    entries = v.list(tag=args.tag)
    if not entries:
        print(f"\n{DIM}  No secrets found.{RESET}\n")
        return

    print(f"\n  {CYAN}{BOLD}{'NAME':<30} {'TAGS':<25} {'UPDATED'}{RESET}")
    print(f"  {DIM}{'─' * 70}{RESET}")
    for e in entries:
        tags = ", ".join(e.tags) if e.tags else DIM + "—" + RESET
        print(f"  {e.name:<30} {tags:<25} {_fmt_time(e.updated_at)}")
    print()


def cmd_search(args):
    v = get_vault(args)
    pw = prompt_password()
    v.unlock(pw)

    results = v.search(args.query)
    if not results:
        print(f"\n{DIM}  No matches for '{args.query}'.{RESET}\n")
        return

    print(f"\n  Found {GREEN}{len(results)}{RESET} result(s) for '{args.query}':\n")
    for e in results:
        print(f"  {CYAN}{e.name}{RESET}  {DIM}{', '.join(e.tags)}{RESET}")
    print()


def cmd_rotate(args):
    v = get_vault(args)
    pw = prompt_password()
    v.unlock(pw)

    new_value = generate_password(args.length, not args.no_symbols)
    v.rotate(args.name, new_value)
    print(f"\n{GREEN}  ✓ '{args.name}' rotated.{RESET}")
    print(f"  New value: {BOLD}{new_value}{RESET}\n")


def cmd_stats(args):
    v = get_vault(args)
    pw = prompt_password()
    v.unlock(pw)

    s = v.stats()
    print(f"\n  {CYAN}{BOLD}Vault Statistics{RESET}")
    print(f"  {DIM}{'─' * 30}{RESET}")
    print(f"  Secrets:    {s['total_secrets']}")
    print(f"  Tags:       {', '.join(s['tags']) or '—'}")
    print(f"  File size:  {s['vault_size_kb']} KB")
    print(f"  Location:   {v.path}\n")


def cmd_generate(args):
    pw = generate_password(args.length, not args.no_symbols)
    print(f"\n  {BOLD}{pw}{RESET}\n")
    print(f"  {DIM}Entropy: ~{len(pw) * 6} bits{RESET}\n")


def _fmt_time(ts: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


# ── Parser ────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(prog="ciphervault", description="CipherVault — Encrypted Secrets Manager")
    p.add_argument("--vault", metavar="PATH", help="Vault file path (default: ~/.ciphervault/default.cvlt)")
    sub = p.add_subparsers(dest="command", required=True)

    # init
    sub.add_parser("init", help="Create a new vault")

    # set
    s = sub.add_parser("set", help="Store a secret")
    s.add_argument("name",             help="Secret name / key")
    s.add_argument("value",  nargs="?", help="Secret value (omit for interactive prompt)")
    s.add_argument("--tags",            help="Comma-separated tags")
    s.add_argument("--note",            help="Optional note")
    s.add_argument("--generate", "-g", action="store_true", help="Generate a random value")
    s.add_argument("--length",  "-l", type=int, default=24, help="Generated password length")
    s.add_argument("--no-symbols",     action="store_true")

    # get
    g = sub.add_parser("get", help="Retrieve a secret")
    g.add_argument("name")
    g.add_argument("--raw", "-r", action="store_true", help="Print value only (pipe-friendly)")

    # delete
    d = sub.add_parser("delete", help="Delete a secret")
    d.add_argument("name")

    # list
    l = sub.add_parser("list", help="List all secrets")
    l.add_argument("--tag", "-t", help="Filter by tag")

    # search
    sr = sub.add_parser("search", help="Search secrets")
    sr.add_argument("query")

    # rotate
    rt = sub.add_parser("rotate", help="Rotate a secret's value")
    rt.add_argument("name")
    rt.add_argument("--length", "-l", type=int, default=32)
    rt.add_argument("--no-symbols", action="store_true")

    # stats
    sub.add_parser("stats", help="Show vault statistics")

    # generate (standalone, no vault needed)
    gp = sub.add_parser("generate", help="Generate a random password (no vault)")
    gp.add_argument("--length", "-l", type=int, default=24)
    gp.add_argument("--no-symbols", action="store_true")

    args = p.parse_args()
    handlers = {
        "init": cmd_init, "set": cmd_set, "get": cmd_get,
        "delete": cmd_delete, "list": cmd_list, "search": cmd_search,
        "rotate": cmd_rotate, "stats": cmd_stats, "generate": cmd_generate,
    }
    try:
        handlers[args.command](args)
    except KeyboardInterrupt:
        print(f"\n{DIM}  Interrupted.{RESET}\n")
    except Exception as e:
        print(f"\n{RED}  Error: {e}{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
