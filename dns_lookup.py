import sys
import threading

import dns.exception
import dns.resolver

from state import save_state


_OUTPUT_LOCK = threading.Lock()


def _dns_status(message, verbose):
    if not verbose:
        return

    with _OUTPUT_LOCK:
        if sys.stdout.isatty():
            sys.stdout.write(f"\r\033[2K{message}")
            sys.stdout.flush()
        else:
            print(message, flush=True)


def _build_resolver(dns_servers=None):
    resolver = dns.resolver.Resolver()

    if dns_servers:
        resolver.nameservers = dns_servers

    return resolver


def _query_records(resolver, hostname, record_type):
    try:
        answers = resolver.resolve(
            hostname,
            record_type,
            search=False,
        )
    except dns.exception.DNSException as error:
        return [], str(error)

    records = []

    for answer in answers:
        if record_type == "A":
            value = answer.address
        elif record_type == "CNAME":
            value = answer.target.to_text(omit_final_dot=True)
        elif record_type == "MX":
            value = (
                f"{answer.preference} "
                f"{answer.exchange.to_text(omit_final_dot=True)}"
            )
        elif record_type == "TXT":
            value = "".join(
                part.decode("utf-8", errors="replace")
                if isinstance(part, bytes)
                else str(part)
                for part in answer.strings
            )
        else:
            value = answer.to_text()

        records.append(value)

    return sorted(set(records)), None


def _ensure_dns_state(state):
    dns_state = state.setdefault("dns", {})

    for key in (
        "a_records",
        "cnames",
        "mx_records",
        "txt_records",
        "dmarc_records",
        "failed",
    ):
        if not isinstance(dns_state.get(key), dict):
            dns_state[key] = {}

    return dns_state


def _failure_key(hostname, record_type):
    return f"{record_type}:{hostname}"


def _record_lookup(
    resolver,
    hostname,
    record_type,
    destination,
    failures,
    state,
    state_file,
    verbose,
):
    failure_key = _failure_key(hostname, record_type)

    if hostname in destination or failure_key in failures:
        return

    _dns_status(
        f"DNS: {record_type} {hostname}",
        verbose,
    )

    records, error = _query_records(
        resolver,
        hostname,
        record_type,
    )

    if records:
        destination[hostname] = records
        failures.pop(failure_key, None)
    else:
        failures[failure_key] = {
            "hostname": hostname,
            "record_type": record_type,
            "error": error or "No records returned",
        }

    save_state(state_file, state)


def _discovered_subdomains(state):
    hostnames = set()

    for result in state.get("completed", {}).values():
        if not isinstance(result, dict):
            continue

        for hostname in result.get("subdomains", []):
            if isinstance(hostname, str) and hostname:
                hostnames.add(hostname.rstrip("."))

    return sorted(hostnames)


def _remember_base_domains(state, domains):
    base_domains = state.setdefault("base_domains", [])

    if not isinstance(base_domains, list):
        base_domains = []
        state["base_domains"] = base_domains

    known_domains = {
        domain.rstrip(".")
        for domain in base_domains
        if isinstance(domain, str) and domain
    }

    for domain in domains:
        domain = domain.strip().rstrip(".")
        if domain:
            known_domains.add(domain)

    state["base_domains"] = sorted(known_domains)


def resolve_dns_records(
    domains,
    state,
    state_file,
    dns_servers=None,
    verbose=False,
):
    """
    Resolve A and CNAME records for certificate-discovered subdomains.
    """
    _remember_base_domains(state, domains)

    dns_state = _ensure_dns_state(state)
    resolver = _build_resolver(dns_servers)

    for hostname in _discovered_subdomains(state):
        _record_lookup(
            resolver=resolver,
            hostname=hostname,
            record_type="A",
            destination=dns_state["a_records"],
            failures=dns_state["failed"],
            state=state,
            state_file=state_file,
            verbose=verbose,
        )

        _record_lookup(
            resolver=resolver,
            hostname=hostname,
            record_type="CNAME",
            destination=dns_state["cnames"],
            failures=dns_state["failed"],
            state=state,
            state_file=state_file,
            verbose=verbose,
        )

    save_state(state_file, state)
    _dns_status("DNS: A and CNAME lookups complete", verbose)

    if verbose and sys.stdout.isatty():
        sys.stdout.write("\n")
        sys.stdout.flush()


def resolve_email_records(
    domains,
    state,
    state_file,
    dns_servers=None,
    verbose=False,
):
    """
    Resolve MX and TXT records for base domains and TXT records for
    _dmarc.<base-domain>.
    """
    _remember_base_domains(state, domains)

    dns_state = _ensure_dns_state(state)
    resolver = _build_resolver(dns_servers)

    for domain in domains:
        domain = domain.strip().rstrip(".")
        if not domain:
            continue

        _record_lookup(
            resolver=resolver,
            hostname=domain,
            record_type="MX",
            destination=dns_state["mx_records"],
            failures=dns_state["failed"],
            state=state,
            state_file=state_file,
            verbose=verbose,
        )

        _record_lookup(
            resolver=resolver,
            hostname=domain,
            record_type="TXT",
            destination=dns_state["txt_records"],
            failures=dns_state["failed"],
            state=state,
            state_file=state_file,
            verbose=verbose,
        )

        dmarc_hostname = f"_dmarc.{domain}"

        _record_lookup(
            resolver=resolver,
            hostname=dmarc_hostname,
            record_type="TXT",
            destination=dns_state["dmarc_records"],
            failures=dns_state["failed"],
            state=state,
            state_file=state_file,
            verbose=verbose,
        )

    save_state(state_file, state)
    _dns_status("DNS: email-record lookups complete", verbose)

    if verbose and sys.stdout.isatty():
        sys.stdout.write("\n")
        sys.stdout.flush()