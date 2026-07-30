import csv
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone


STATE_VERSION = 3
_OUTPUT_DIR = "."


def set_output_dir(output_dir):
    global _OUTPUT_DIR
    _OUTPUT_DIR = os.path.abspath(output_dir)
    os.makedirs(_OUTPUT_DIR, exist_ok=True)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def new_state():
    timestamp = utc_now()

    return {
        "application": "AyeAye.py",
        "version": STATE_VERSION,
        "created_at": timestamp,
        "updated_at": timestamp,
        "base_domains": [],
        "completed": {},
        "failed": [],
        "dns": {
            "a_records": {},
            "cnames": {},
            "mx_records": {},
            "txt_records": {},
            "dmarc_records": {},
            "failed": {},
        },
    }


def _merge_defaults(state):
    """
    Add missing fields without removing or replacing unknown fields.
    This keeps the state format backward- and forward-compatible.
    """
    defaults = new_state()

    for key, value in defaults.items():
        if key not in state:
            state[key] = value

    if not isinstance(state["base_domains"], list):
        state["base_domains"] = []

    if not isinstance(state["completed"], dict):
        state["completed"] = {}

    if not isinstance(state["failed"], list):
        state["failed"] = []

    if not isinstance(state["dns"], dict):
        state["dns"] = {}

    for key, value in defaults["dns"].items():
        if key not in state["dns"]:
            state["dns"][key] = value

    for key in (
        "a_records",
        "cnames",
        "mx_records",
        "txt_records",
        "dmarc_records",
        "failed",
    ):
        if not isinstance(state["dns"].get(key), dict):
            state["dns"][key] = {}

    current_version = state.get("version", 0)
    if not isinstance(current_version, int):
        current_version = 0

    state["version"] = max(current_version, STATE_VERSION)

    return state


def load_state(filename):
    if not os.path.exists(filename):
        return new_state()

    try:
        with open(filename, "r", encoding="utf-8") as state_file:
            state = json.load(state_file)
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"could not load state file '{filename}': {error}"
        ) from error

    if not isinstance(state, dict):
        raise RuntimeError(
            f"state file '{filename}' must contain a JSON object"
        )

    return _merge_defaults(state)


def backup_state(filename):
    if not os.path.exists(filename):
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"{filename}.{timestamp}.bak"

    shutil.copy2(filename, backup_filename)
    return backup_filename


def atomic_write_json(filename, data):
    directory = os.path.dirname(os.path.abspath(filename)) or "."
    os.makedirs(directory, exist_ok=True)

    descriptor, temporary_filename = tempfile.mkstemp(
        prefix=".ayeaye_state_",
        suffix=".tmp",
        dir=directory,
        text=True,
    )

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as state_file:
            json.dump(data, state_file, indent=2, sort_keys=True)
            state_file.write("\n")
            state_file.flush()
            os.fsync(state_file.fileno())

        os.replace(temporary_filename, filename)

    except Exception:
        try:
            os.unlink(temporary_filename)
        except OSError:
            pass

        raise


def save_state(filename, state):
    state = _merge_defaults(state)
    state["updated_at"] = utc_now()
    state["failed"] = sorted(set(state["failed"]))

    atomic_write_json(filename, state)
    save_outputs(state)


def _collect_certificate_values(state, key):
    values = set()

    for result in state.get("completed", {}).values():
        if not isinstance(result, dict):
            continue

        for value in result.get(key, []):
            if isinstance(value, str) and value:
                values.add(value)

    return sorted(values)


def _write_lines(filename, lines):
    with open(filename, "w", encoding="utf-8") as output_file:
        if lines:
            output_file.write("\n".join(lines))
            output_file.write("\n")


def _record_values(records, hostname):
    values = records.get(hostname, [])

    if isinstance(values, list):
        return " | ".join(
            sorted(str(value) for value in values)
        )

    if values is None:
        return ""

    return str(values)


def _write_csv(filename, fieldnames, rows):
    with open(filename, "w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=fieldnames,
            extrasaction="ignore",
            delimiter="\t"
        )
        writer.writeheader()
        writer.writerows(rows)


def _normalise_domain(value):
    if not isinstance(value, str):
        return ""

    return value.strip().rstrip(".")


def _primary_domains(state):
    domains = set()

    for domain in state.get("base_domains", []):
        domain = _normalise_domain(domain)
        if domain:
            domains.add(domain)

    dns = state.get("dns", {})

    for hostname in dns.get("mx_records", {}):
        hostname = _normalise_domain(hostname)
        if hostname:
            domains.add(hostname)

    for hostname in dns.get("txt_records", {}):
        hostname = _normalise_domain(hostname)
        if hostname:
            domains.add(hostname)

    for hostname in dns.get("dmarc_records", {}):
        hostname = _normalise_domain(hostname)

        if hostname.startswith("_dmarc."):
            hostname = hostname[len("_dmarc."):]

        if hostname:
            domains.add(hostname)

    return sorted(domains)


def _write_primary_domain_csv(state):
    dns = state.get("dns", {})
    rows = []

    for domain in _primary_domains(state):
        rows.append({
            "domain": domain,
            "mx": _record_values(
                dns.get("mx_records", {}),
                domain,
            ),
            "txt": _record_values(
                dns.get("txt_records", {}),
                domain,
            ),
            "dmarc_txt": _record_values(
                dns.get("dmarc_records", {}),
                f"_dmarc.{domain}",
            ),
        })

    _write_csv(
        os.path.join(_OUTPUT_DIR, "primary_domain_records.csv"),
        ["domain", "mx", "txt", "dmarc_txt"],
        rows,
    )


def _discovered_subdomains(state):
    hostnames = set()

    for result in state.get("completed", {}).values():
        if not isinstance(result, dict):
            continue

        for hostname in result.get("subdomains", []):
            hostname = _normalise_domain(hostname)
            if hostname:
                hostnames.add(hostname)

    return hostnames


def _write_subdomain_csv(state):
    dns = state.get("dns", {})
    hostnames = _discovered_subdomains(state)

    for record_type in ("a_records", "cnames"):
        for hostname in dns.get(record_type, {}):
            hostname = _normalise_domain(hostname)
            if hostname:
                hostnames.add(hostname)

    rows = []

    for hostname in sorted(hostnames):
        rows.append({
            "hostname": hostname,
            "a_records": _record_values(
                dns.get("a_records", {}),
                hostname,
            ),
            "cname": _record_values(
                dns.get("cnames", {}),
                hostname,
            ),
        })

    _write_csv(
        os.path.join(_OUTPUT_DIR, "subdomain_records.csv"),
        ["hostname", "a_records", "cname"],
        rows,
    )


def save_outputs(state):
    os.makedirs(_OUTPUT_DIR, exist_ok=True)

    _write_lines(
        os.path.join(_OUTPUT_DIR, "subdomains.txt"),
        _collect_certificate_values(state, "subdomains"),
    )

    _write_lines(
        os.path.join(_OUTPUT_DIR, "wildcards.txt"),
        _collect_certificate_values(state, "wildcards"),
    )

    _write_primary_domain_csv(state)
    _write_subdomain_csv(state)