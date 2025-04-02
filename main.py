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

    for origin in origins:
        try:
            headers = {'Origin': origin, 'User-Agent': user_agent}
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')

            if acao:
                if verbosity >= 1:
                    logging.info(f"Origin: {origin}")
                    logging.info(f"Access-Control-Allow-Origin: {acao}")
                    if acac:
                        logging.info(f"Access-Control-Allow-Credentials: {acac}")
                    else:
                         logging.info("Access-Control-Allow-Credentials: Not Present")

                if acao == '*':
                    logging.warning(f"Potential CORS vulnerability: Wildcard (*) is used for Access-Control-Allow-Origin with Origin: {origin}")
                elif origin in acao:
                    logging.info(f"CORS configured correctly for origin: {origin}")
                elif acao != 'null' and acao != origin and acao != None:
                    logging.warning(f"Potential CORS vulnerability: Access-Control-Allow-Origin is set to {acao} which doesn't match the origin {origin}")
                elif acao == 'null' and origin == 'null':
                    logging.info("CORS configured correctly for origin: null")
                elif acao == 'null' and origin != 'null':
                    logging.warning("Potential CORS vulnerability: Null origin allowed, but a specific origin was requested.")


            else:
                if verbosity >= 2:
                    logging.info(f"No Access-Control-Allow-Origin header found for origin: {origin}")

        except requests.exceptions.RequestException as e:
            if verbosity >= 0: # always log errors
                logging.error(f"Error for origin {origin}: {e}")
        except Exception as e:
             if verbosity >= 0: # always log errors
                logging.error(f"An unexpected error occurred for origin {origin}: {e}")



def main():
    """
    Main function to execute the CORS scanner.
    """
    args = setup_argparse()

    if not is_valid_url(args.url):
        logging.error("Invalid URL provided. Please provide a valid URL.")
        sys.exit(1)

    if not all(re.match(r'^https?://', o) or o == 'null' for o in args.origins):
        logging.error("Invalid origin provided. Origins must start with http://, https:// or be 'null'.")
        sys.exit(1)


    scan_cors(args.url, args.origins, args.user_agent, args.timeout, args.allow_redirects, args.verbosity)

if __name__ == "__main__":
    # Usage examples:
    # python main.py http://example.com
    # python main.py http://example.com --origins http://evil.com http://localhost
    # python main.py http://example.com --user-agent MyCustomAgent
    # python main.py http://example.com --timeout 5
    # python main.py http://example.com --allow-redirects
    # python main.py http://example.com --verbosity 2
    main()