import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


MAX_RETRIES = 20
DEFAULT_RETRY_DELAY = 2

_OUTPUT_LOCK = threading.Lock()
_STATUS_LINES = {}


def _display_status(worker_id, domain, status, verbose):
    if not verbose:
        return

    line = f"Worker {worker_id}: {domain} - {status}"

    with _OUTPUT_LOCK:
        _STATUS_LINES[worker_id] = line

        if not sys.stdout.isatty():
            print(line, flush=True)
            return

        worker_ids = sorted(_STATUS_LINES)
        line_count = len(worker_ids)

        if line_count > 1:
            sys.stdout.write(f"\033[{line_count - 1}A")

        for current_worker_id in worker_ids:
            sys.stdout.write("\r\033[2K")
            sys.stdout.write(_STATUS_LINES[current_worker_id])
            sys.stdout.write("\n")

        sys.stdout.flush()


def _initialise_status_lines(worker_count, verbose):
    if not verbose or not sys.stdout.isatty():
        return

    with _OUTPUT_LOCK:
        _STATUS_LINES.clear()

        for worker_id in range(1, worker_count + 1):
            _STATUS_LINES[worker_id] = f"Worker {worker_id}: waiting"

        for worker_id in range(worker_count):
            sys.stdout.write("\033[2K\n")

        sys.stdout.write(f"\033[{worker_count}A")
        sys.stdout.flush()


def _finish_status_lines(verbose):
    if not verbose or not sys.stdout.isatty():
        return

    with _OUTPUT_LOCK:
        if _STATUS_LINES:
            sys.stdout.write("\n")
            sys.stdout.flush()


def _request_domain(domain, proxies, worker_id, verbose):
    last_error = "unknown error"

    for attempt in range(1, MAX_RETRIES + 2):
        _display_status(
            worker_id,
            domain,
            f"request {attempt}/{MAX_RETRIES + 1}",
            verbose,
        )

        try:
            response = requests.get(
                f"https://crt.sh/json?q={domain}",
                timeout=100,
                proxies=proxies,
            )

            if response.status_code == 200:
                return response.json()

            last_error = f"HTTP status {response.status_code}"

        except (requests.RequestException, ValueError) as error:
            last_error = str(error)

        if attempt <= MAX_RETRIES:
            _display_status(
                worker_id,
                domain,
                f"retrying: {last_error}",
                verbose,
            )
            time.sleep(DEFAULT_RETRY_DELAY * min(attempt, 5))

    raise RuntimeError(last_error)


def _parse_certificate_data(domain_data):
    subdomains = set()
    wildcards = set()

    if not isinstance(domain_data, list):
        raise ValueError("crt.sh returned an unexpected JSON structure")

    for result in domain_data:
        if not isinstance(result, dict):
            continue

        names = []

        common_name = result.get("common_name")
        if common_name:
            names.append(common_name)

        name_value = result.get("name_value")
        if name_value:
            names.extend(str(name_value).splitlines())

        for name in names:
            name = name.strip().rstrip(".")
            if not name:
                continue

            if name.startswith("*."):
                wildcards.add(name)
            else:
                subdomains.add(name)

    return sorted(subdomains), sorted(wildcards)


def _resolve_domain(task):
    domain, proxies, worker_id, verbose = task

    _display_status(worker_id, domain, "working", verbose)

    try:
        domain_data = _request_domain(
            domain=domain,
            proxies=proxies,
            worker_id=worker_id,
            verbose=verbose,
        )
        subdomains, wildcards = _parse_certificate_data(domain_data)

    except Exception as error:
        _display_status(worker_id, domain, "failed", verbose)

        return {
            "domain": domain,
            "success": False,
            "error": str(error),
        }

    _display_status(worker_id, domain, "resolved", verbose)

    return {
        "domain": domain,
        "success": True,
        "subdomains": subdomains,
        "wildcards": wildcards,
    }


def process_domains(
    domains,
    state,
    state_file,
    workers,
    proxies=None,
    verbose=False,
):
    """
    Resolve domains not already completed in state.

    State is updated and saved after every domain result. The worker threads
    perform network requests only; state mutation and file writes happen in
    the main thread.
    """
    completed = state.setdefault("completed", {})
    failed = state.setdefault("failed", [])

    pending_domains = [
        domain for domain in domains
        if domain not in completed
    ]

    if not pending_domains:
        return

    worker_count = min(workers, len(pending_domains))
    _initialise_status_lines(worker_count, verbose)

    tasks = [
        (
            domain,
            proxies,
            worker_id,
            verbose,
        )
        for worker_id, domain in enumerate(pending_domains, start=1)
    ]

    try:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [
                executor.submit(_resolve_domain, task)
                for task in tasks
            ]

            for future in as_completed(futures):
                result = future.result()
                domain = result["domain"]

                if result["success"]:
                    completed[domain] = {
                        "subdomains": result["subdomains"],
                        "wildcards": result["wildcards"],
                    }

                    while domain in failed:
                        failed.remove(domain)

                    print(
                        f"{domain}: "
                        f"{len(result['subdomains'])} subdomains, "
                        f"{len(result['wildcards'])} wildcards"
                    )
                else:
                    if domain not in failed:
                        failed.append(domain)

                    print(
                        f"{domain}: failed after "
                        f"{MAX_RETRIES} retries"
                    )

                    if verbose:
                        print(f"  Reason: {result['error']}")

                from state import save_state

                save_state(state_file, state)

    finally:
        _finish_status_lines(verbose)