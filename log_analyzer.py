import re
from collections import defaultdict
from typing import Dict, List, Tuple, Set


LOG_FILE = 'sample_access.log'
TOP_N_LIMIT = 5 # Number of items to display in Top IP/Path lists


LOG_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - ' 
    r'\[(?P<datetime>.*?)\] '
    r'"(?P<method>\w+) (?P<path>.*?) (?P<protocol>.*?)" '
    r'(?P<status>\d{3}) (?P<size>(\d+|-)) ' # MODIFIED: Allow '-' for size (e.g., 304 responses)
    r'"(?P<referrer>.*?)" '
    r'"(?P<user_agent>.*?)"'
)

def analyze_log_file(filepath: str) -> Dict:
    stats = {
        "total_requests": 0,
        "total_bytes": 0,
        "ip_counts": defaultdict(int),
        "status_counts": defaultdict(int),
        "top_paths": defaultdict(int),
        "error_statuses": {'4xx': 0, '5xx': 0},

        "suspicious_requests": defaultdict(set), 
    }
    
    print(f"--- Analyzing Log File: {filepath} ---")

    try:
        with open(filepath, 'r') as f:
            for line in f:
                stats["total_requests"] += 1
                match = LOG_PATTERN.match(line)
                
                if match:
                    data = match.groupdict()
                    status = data['status']
                    size_str = data['size']
                    size = int(size_str) if size_str != '-' else 0
                    stats["total_bytes"] += size
                    

                    stats["ip_counts"][data['ip']] += 1
                    

                    stats["status_counts"][status] += 1
                    

                    path = data['path'].split('?')[0]
                    stats["top_paths"][path] += 1

                    if status.startswith('4'):
                        stats["error_statuses"]['4xx'] += 1

                        stats["suspicious_requests"][data['ip']].add((path, status))
                    elif status.startswith('5'):
                        stats["error_statuses"]['5xx'] += 1

    except FileNotFoundError:
        print(f"ERROR: The file '{filepath}' was not found. Please ensure 'sample_access.log' is in the same directory.")
        return {}
    except Exception as e:
        print(f"An unexpected error occurred during file reading: {e}")
        return {}
    
    return stats

def format_bytes(bytes_val):

    if bytes_val >= 1024**3:
        return f"{bytes_val / 1024**3:.2f} GB"
    elif bytes_val >= 1024**2:
        return f"{bytes_val / 1024**2:.2f} MB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.2f} KB"
    else:
        return f"{bytes_val} Bytes"

def display_report(stats: Dict):

    if not stats:
        return
        
    print("\n" + "="*60)
    print("                 WEB ACCESS LOG ANALYSIS REPORT")
    print("="*60)


    def get_top_items(d: Dict[str, int], limit: int) -> List[Tuple[str, int]]:
        return sorted(d.items(), key=lambda item: item[1], reverse=True)[:limit]


    print(f"\n[ SUMMARY ]")
    print(f"Total Requests Processed: {stats['total_requests']}")
    print(f"Unique IP Addresses: {len(stats['ip_counts'])}")
    print(f"Total Data Transferred: {format_bytes(stats['total_bytes'])}") # New metric
    print(f"Total Client Errors (4xx): {stats['error_statuses']['4xx']}")
    print(f"Total Server Errors (5xx): {stats['error_statuses']['5xx']}")
    

    print(f"\n[ TOP {TOP_N_LIMIT} IP ADDRESSES ] (Possible high-traffic sources)")
    for ip, count in get_top_items(stats['ip_counts'], TOP_N_LIMIT):
        print(f"  - {ip}: {count} requests")


    suspicious_ips = stats['suspicious_requests']
    has_alert = any(len(unique_requests) > 1 for unique_requests in suspicious_ips.values())

    if has_alert:
        print("\n" + "#"*60)
        print("🚨 SECURITY ALERT: 4XX ERROR ANALYSIS (Possible Scanning)")
        print(f"IPs with multiple unique failed attempts: {len([ip for ip, reqs in suspicious_ips.items() if len(reqs) > 1])}")
        print("#"*60)
        
        for ip, unique_requests in suspicious_ips.items():

            if len(unique_requests) > 1:
                print(f"  - IP: {ip} (Unique failed attempts: {len(unique_requests)})")

                for path, status in list(unique_requests)[:3]:
                    print(f"    -> Status {status}: {path}")

    print(f"\n[ TOP STATUS CODES ]")
    for status, count in get_top_items(stats['status_counts'], 10):
        description = "OK" if status == '200' else \
                      "Not Found" if status == '404' else \
                      "Redirect" if status.startswith('3') else \
                      "Server Error" if status.startswith('5') else \
                      "Other"
        print(f"  - {status} ({description}): {count} hits")

    print(f"\n[ TOP {TOP_N_LIMIT} REQUESTED PATHS ]")
    for path, count in get_top_items(stats['top_paths'], TOP_N_LIMIT):
        display_path = path if len(path) < 50 else path[:47] + "..."
        print(f"  - {display_path}: {count} hits")
        
    print("="*60)


if __name__ == "__main__":
    analysis_results = analyze_log_file(LOG_FILE)
    display_report(analysis_results)
