# vuln-CORS-Misconfiguration-Scanner
Scans for common CORS misconfigurations by sending requests with different origin headers and analyzing the `Access-Control-Allow-Origin` response header to identify overly permissive or wildcard configurations. Uses `requests`.

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-cors-misconfiguration-scanner`

`pip install -r requirements.txt`

## Usage
`python main.py <url> [params]`

Example: `python main.py http://127.0.0.1:8080/cors`

## Parameters
- `url`: The URL to scan for CORS misconfigurations (required, positional).
- `-h`: Show help message and exit
- `--origins`: A list of origin headers to test with. Default: http://evil.com http://localhost null
- `--user-agent`: The User-Agent string to use. Default: vuln-CORS-Misconfiguration-Scanner/1.0
- `--timeout`: Timeout in seconds for each request. Default: 10. Must be greater than 0.
- `--allow-redirects`: Follow redirects
- `--verbosity`: Verbosity level: 0 (errors only), 1 (default, errors and basic info), 2 (debug). Default: 1

## Verdicts
- An origin reflected in `Access-Control-Allow-Origin` is a vulnerability, and a critical one when `Access-Control-Allow-Credentials: true` accompanies it.
- An allowed `null` origin is a vulnerability, critical with credentials.
- A wildcard `*` is a potential vulnerability, critical with credentials.
- A fixed allow origin that does not match the probe origin is not a finding.
- CORS headers are read on every response, including error responses. If no probe reaches the target, the run exits non-zero with no verdict.

## License
MIT License (see LICENSE).
