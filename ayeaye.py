#!/usr/bin/env python3

import argparse
import glob
import os
import shutil
import sys

from crtsh import process_domains
from dns_lookup import resolve_email_records, resolve_dns_records
from state import load_state, new_state, save_state, set_output_dir


PROJECT_NAME = "AyeAye.py"
DEFAULT_OUTPUT_DIR = "./output"
DEFAULT_STATE_NAME = "ayeaye_state.json"

BANNER = r""" ~  / \  ~
   ( ~ )
  ( .*. )
 ( @ _ @ )
(_________)"""

LEGACY_FILES = (
    "ayeaye_state.json",
    "subdomains.txt",
    "wildcards.txt",
    "primary_domain_records.csv",
    "subdomain_records.csv",
)


def print_banner(verbose=False):
    if verbose and sys.stdout.isatty():
        print(f"\033[36m{BANNER}\033[0m")
    else:
        print(BANNER)


def parse_args():
    parser = argparse.ArgumentParser(
        prog="ayeaye.py",
        description=(
            f"{PROJECT_NAME}: threaded certificate and optional DNS lookups "
            "with resumable state."
        ),
    )

    parser.add_argument(
        "domain_list",
        help="File containing one base domain per line",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=5,
        help="Number of concurrent certificate lookups (default: 5)",
    )
    parser.add_argument(
        "--state",
        default=DEFAULT_STATE_NAME,
        help=f"State file name or path (default: {DEFAULT_STATE_NAME})",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Start a new state while preserving the existing state file",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show live worker and DNS status",
    )

    proxy_group = parser.add_argument_group("proxy options")
    proxy_group.add_argument(
        "--proxy",
        help="Proxy used for both HTTP and HTTPS requests",
    )
    proxy_group.add_argument(
        "--http-proxy",
        help="Proxy used for HTTP requests",
    )
    proxy_group.add_argument(
        "--https-proxy",
        help="Proxy used for HTTPS requests",
    )

    dns_group = parser.add_argument_group("DNS options")
    dns_group.add_argument(
        "--resolve-records",
        action="store_true",
        help="Resolve A and CNAME records for discovered subdomains",
    )
    dns_group.add_argument(
        "--resolve-email-records",
        action="store_true",
        help=(
            "Resolve MX, TXT, and DMARC TXT records for base domains"
        ),
    )
    dns_group.add_argument(
        "--dns-server",
        action="append",
        dest="dns_servers",
        metavar="ADDRESS",
        help="DNS server address; may be specified more than once",
    )
    dns_group.add_argument(
        "--all",
        action="store_true",
        help="Enable all optional DNS features",
    )

    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be at least 1")

    if args.all:
        args.resolve_records = True
        args.resolve_email_records = True

    return args


def load_domains(filename):
    try:
        with open(filename, "r", encoding="utf-8") as domain_file:
            domains = []

            for line in domain_file:
                domain = line.strip().rstrip(".")
                if domain:
                    domains.append(domain)

            return list(dict.fromkeys(domains))

    except OSError as error:
        raise RuntimeError(
            f"could not read domain list '{filename}': {error}"
        ) from error


def build_proxies(args):
    http_proxy = args.http_proxy or args.proxy
    https_proxy = args.https_proxy or args.proxy

    if not http_proxy and not https_proxy:
        return None

    return {
        "http": http_proxy,
        "https": https_proxy,
    }


def resolve_state_path(output_dir, state_argument):
    if os.path.isabs(state_argument):
        return state_argument

    return os.path.join(output_dir, state_argument)


def migrate_legacy_files(output_dir, explicit_state):
    if explicit_state:
        return

    output_state = os.path.join(output_dir, DEFAULT_STATE_NAME)

    if os.path.exists(output_state):
        return

    legacy_state = DEFAULT_STATE_NAME

    if not os.path.exists(legacy_state):
        return

    os.makedirs(output_dir, exist_ok=True)

    print(
        f"Legacy state detected: {legacy_state}. "
        f"Attempting migration to {output_dir}."
    )

    filenames = list(LEGACY_FILES)
    filenames.extend(glob.glob(f"{legacy_state}.*.bak"))

    for filename in filenames:
        if not os.path.exists(filename):
            continue

        destination = os.path.join(
            output_dir,
            os.path.basename(filename),
        )

        if os.path.exists(destination):
            print(
                "Migration skipped; destination already exists: "
                f"{destination}"
            )
            continue

        try:
            shutil.move(filename, destination)
            print(f"Moved {filename} -> {destination}")
        except OSError as error:
            print(f"Could not move {filename}: {error}")


def main():
    args = parse_args()
    print_banner(args.verbose)

    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    explicit_state = (
        args.state != DEFAULT_STATE_NAME
        or os.path.isabs(args.state)
    )

    migrate_legacy_files(
        output_dir=output_dir,
        explicit_state=explicit_state,
    )

    state_file = resolve_state_path(output_dir, args.state)
    set_output_dir(output_dir)

    try:
        domains = load_domains(args.domain_list)
    except RuntimeError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    if not domains:
        print(
            "Error: the domain list contains no domains.",
            file=sys.stderr,
        )
        return 1

    try:
        if args.fresh:
            state = new_state()
        else:
            state = load_state(state_file)

        state.setdefault("base_domains", [])
        known_base_domains = {
            domain.rstrip(".")
            for domain in state["base_domains"]
            if isinstance(domain, str) and domain
        }
        state["base_domains"] = sorted(
            known_base_domains.union(domains)
        )

        proxies = build_proxies(args)

        process_domains(
            domains=domains,
            state=state,
            state_file=state_file,
            workers=args.workers,
            proxies=proxies,
            verbose=args.verbose,
        )

        while True:
            failed_domains = sorted(
                set(state.get("failed", [])).intersection(domains)
            )

            if not failed_domains:
                break

            print("\nFailed domains requiring retries:")
            for domain in failed_domains:
                print(f"  - {domain}")

            answer = input(
                "\nRetry failed domains? [y/N] "
            ).strip().lower()

            if answer not in {"y", "yes"}:
                break

            process_domains(
                domains=failed_domains,
                state=state,
                state_file=state_file,
                workers=args.workers,
                proxies=proxies,
                verbose=args.verbose,
            )

        if args.resolve_records:
            resolve_dns_records(
                domains=domains,
                state=state,
                state_file=state_file,
                dns_servers=args.dns_servers,
                verbose=args.verbose,
            )

        if args.resolve_email_records:
            resolve_email_records(
                domains=domains,
                state=state,
                state_file=state_file,
                dns_servers=args.dns_servers,
                verbose=args.verbose,
            )

        save_state(state_file, state)

    except KeyboardInterrupt:
        print(
            "\nInterrupted. Progress has been retained.",
            file=sys.stderr,
        )
        return 130

    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    unresolved = sorted(
        set(state.get("failed", [])).intersection(domains)
    )

    if unresolved:
        print("\nUnresolved domains:")
        for domain in unresolved:
            print(f"  - {domain}")
    else:
        print("\nAll requested domains resolved successfully.")

    print(f"State retained in: {state_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())