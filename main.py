import argparse
import requests
import logging
import sys
import re
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Scans for common CORS misconfigurations.')
    parser.add_argument('url', type=str, help='The URL to scan for CORS misconfigurations.')
    parser.add_argument('--origins', type=str, nargs='+', default=['http://evil.com', 'http://localhost', 'null'],
                        help='A list of origin headers to test with. Default: http://evil.com http://localhost null')
    parser.add_argument('--user-agent', type=str, default='vuln-CORS-Misconfiguration-Scanner/1.0',
                        help='The User-Agent string to use. Default: vuln-CORS-Misconfiguration-Scanner/1.0')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Timeout in seconds for each request. Default: 10')
    parser.add_argument('--allow-redirects', action='store_true', help='Follow redirects')
    parser.add_argument('--verbosity', type=int, choices=[0, 1, 2], default=1,
                        help='Verbosity level: 0 (errors only), 1 (default - errors and basic info), 2 (debug - verbose output).')
    return parser.parse_args()

def is_valid_url(url):
    """
    Validates if the provided URL is valid.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def scan_cors(url, origins, user_agent, timeout, allow_redirects, verbosity):
    """
    Scans for CORS misconfigurations by sending requests with different origin headers.
    """

    if verbosity >= 1:
        logging.info(f"Scanning URL: {url}")

    reached = 0
    for origin in origins:
        try:
            # A plain GET, never an OPTIONS preflight. I am reading how the
            # server answers an actual cross origin request, so a policy
            # that only shows up on preflight is outside what this sees.
            headers = {'Origin': origin, 'User-Agent': user_agent}
            # No raise_for_status: CORS headers on error responses are read too.
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
            reached += 1

            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')
            # Only the exact word true counts, after trimming and lowering.
            # A header that says yes or 1 is reported as present above but
            # never raises a finding to the credentialed level.
            credentials = bool(acac) and acac.strip().lower() == 'true'

            if acao:
                acao = acao.strip()
                if verbosity >= 1:
                    logging.info(f"Origin: {origin}")
                    logging.info(f"Response status: {response.status_code}")
                    logging.info(f"Access-Control-Allow-Origin: {acao}")
                    if acac:
                        logging.info(f"Access-Control-Allow-Credentials: {acac}")
                    else:
                         logging.info("Access-Control-Allow-Credentials: Not Present")
                logging.debug(f"Raw CORS headers for origin {origin}: ACAO={acao} ACAC={acac}")

                if acao == '*':
                    if credentials:
                        logging.warning(f"CRITICAL CORS vulnerability: Wildcard (*) Access-Control-Allow-Origin with credentials allowed for origin: {origin}")
                    else:
                        logging.warning(f"Potential CORS vulnerability: Wildcard (*) is used for Access-Control-Allow-Origin with Origin: {origin}")
                elif acao == 'null':
                    if credentials:
                        logging.warning(f"CRITICAL CORS vulnerability: Null origin allowed with credentials (Access-Control-Allow-Origin: null) for origin: {origin}")
                    else:
                        logging.warning(f"Potential CORS vulnerability: Null origin allowed (Access-Control-Allow-Origin: null) for origin: {origin}")
                elif acao == origin:
                    if credentials:
                        logging.warning(f"CRITICAL CORS vulnerability: Origin {origin} is reflected with credentials allowed (credentialed reflection)")
                    else:
                        logging.warning(f"Potential CORS vulnerability: Origin {origin} is reflected in Access-Control-Allow-Origin")
                else:
                    logging.info(f"Access-Control-Allow-Origin is set to {acao}, which does not match the probe origin {origin}; a browser would block this origin, so this is not a finding for origin: {origin}")

            else:
                logging.debug(f"No Access-Control-Allow-Origin header found for origin: {origin} (status {response.status_code})")

        except requests.exceptions.RequestException as e:
            logging.error(f"Error for origin {origin}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred for origin {origin}: {e}")

    return reached


def main():
    """
    Main function to execute the CORS scanner.
    """
    args = setup_argparse()

    if not is_valid_url(args.url):
        logging.error("Invalid URL provided. Please provide a valid URL.")
        sys.exit(1)

    # The origin check anchors at the start only. An origin carrying a path
    # or other trailing text passes this gate and is sent as written, which
    # is on the operator: browsers never send such an Origin header.
    if not all(re.match(r'^https?://', o) or o == 'null' for o in args.origins):
        logging.error("Invalid origin provided. Origins must start with http://, https:// or be 'null'.")
        sys.exit(1)


    # Apply the verbosity setting to the logger: 0 errors only, 1 info, 2 debug.
    logging.getLogger().setLevel({0: logging.ERROR, 1: logging.INFO, 2: logging.DEBUG}[args.verbosity])

    reached = scan_cors(args.url, args.origins, args.user_agent, args.timeout, args.allow_redirects, args.verbosity)

    if reached == 0:
        logging.error("No origin probe reached the target. Scan not performed; no verdict is available.")
        sys.exit(1)

if __name__ == "__main__":
    # Usage examples:
    # python main.py http://example.com
    # python main.py http://example.com --origins http://evil.com http://localhost
    # python main.py http://example.com --user-agent MyCustomAgent
    # python main.py http://example.com --timeout 5
    # python main.py http://example.com --allow-redirects
    # python main.py http://example.com --verbosity 2
    main()