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
- `--verbosity`: No description provided

## License
Copyright (c) ShadowStrikeHQ
