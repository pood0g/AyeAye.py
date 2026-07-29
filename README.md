# AyeAye.py
AyeAye.py collects hostnames from crt.sh certificate-transparency data and optionally performs DNS lookups.

## Requirements
Python 3.9 or newer, with:

 - requests
 - dnspython

### Install dependencies:

```
pip install requests dnspython
```

## Basic usage

```
python ayeaye.py domains.txt
```

Output files are written to `./output` by default.

Enable A and CNAME lookups for discovered subdomains:

```
python ayeaye.py domains.txt --resolve-records
```

Enable MX, TXT, and DMARC TXT lookups for base domains:

```
python ayeaye.py domains.txt --resolve-email-records
```

Enable all optional features:

```
python ayeaye.py domains.txt --all
```

Use a proxy:

```
python ayeaye.py domains.txt --proxy socks5h://127.0.0.1:1080
```

## Resume behaviour
Existing results are reused automatically. Use `--fresh` to start a new state. The state file and generated output are retained after completion.

## Warning
Use `AyeAye.py` only against domains and systems that you own or are authorised to assess. Certificate and DNS lookups generate external service traffic. Use conservative worker counts and avoid unnecessary repeated scans.