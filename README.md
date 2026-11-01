# vuln-CORS-Misconfiguration-Scanner
Scans for common CORS misconfigurations by sending requests with different origin headers and analyzing the `Access-Control-Allow-Origin` response header to identify overly permissive or wildcard configurations. Uses `requests`. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-cors-misconfiguration-scanner`

## Usage
`./vuln-cors-misconfiguration-scanner [params]`

## Parameters
- `-h`: Show help message and exit
- `--origins`: A list of origin headers to test with. Default: http://evil.com http://localhost null
- `--user-agent`: The User-Agent string to use. Default: vuln-CORS-Misconfiguration-Scanner/1.0
- `--timeout`: Timeout in seconds for each request. Default: 10
- `--allow-redirects`: Follow redirects
- `--verbosity`: Verbosity level: 0 (errors only), 1 (default, errors and basic info), 2 (debug). Default: 1

## Verdicts
- An origin reflected in `Access-Control-Allow-Origin` is a vulnerability, and a critical one when `Access-Control-Allow-Credentials: true` accompanies it.
- An allowed `null` origin is a vulnerability, critical with credentials.
- A wildcard `*` is a potential vulnerability, critical with credentials.
- A fixed allow origin that does not match the probe origin is not a finding.
- CORS headers are read on every response, including error responses. If no probe reaches the target, the run exits non-zero with no verdict.

## License
Copyright (c) ShadowStrikeHQ
