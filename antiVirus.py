import os
import time
import threading
import requests
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Global set to store hashes of scanned files
scanned_files = set()

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file to identify unique files."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {e}")
        return None

def check_file_with_virustotal(file_path, api_key):
    """Scan file with VirusTotal API and return results"""
    url = 'https://www.virustotal.com/api/v3/files'
    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            headers = {'x-apikey': api_key}
            response = requests.post(url, headers=headers, files=files)
            
            if response.status_code == 200:
                result = response.json()
                print(f"\nFile {file_path} scanned successfully on VirusTotal.")
                
                # Get the analysis ID to retrieve the report
                analysis_id = result.get('data', {}).get('id')
                if analysis_id:
                    # Wait a moment for analysis to complete (VirusTotal needs some time)
                    time.sleep(15)
                    
                    # Get the analysis report
                    report_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
                    report_response = requests.get(report_url, headers=headers)
                    
                    if report_response.status_code == 200:
                        report = report_response.json()
                        stats = report.get('data', {}).get('attributes', {}).get('stats', {})
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        undetected = stats.get('undetected', 0)
                        harmless = stats.get('harmless', 0)
                        
                        print("\nVirusTotal Scan Results:")
                        print(f"Malicious: {malicious}")
                        print(f"Suspicious: {suspicious}")
                        print(f"Undetected: {undetected}")
                        print(f"Harmless: {harmless}")
                        
                        if malicious > 0:
                            print("\n⚠️ WARNING: This file was flagged as malicious by one or more engines!")
                        elif suspicious > 0:
                            print("\n⚠️ CAUTION: This file was flagged as suspicious by one or more engines!")
                        else:
                            print("\n✅ No malicious indicators found.")
                            
                        return report
                    else:
                        print(f"Failed to get report for {file_path}. Status code: {report_response.status_code}")
                return None
            else:
                print(f"Failed to upload file {file_path}. Status code: {response.status_code}")
                return None
    except Exception as e:
        print(f"Error scanning file {file_path} with VirusTotal: {e}")
        return None

def scan_file_path(path, api_key=None):
    """Scan a file or directory, skipping already scanned files"""
    try:
        if os.path.isfile(path):
            file_hash = calculate_file_hash(path)
            if file_hash and file_hash in scanned_files:
                print(f"File already scanned: {path}")
                return
            
            if file_hash:
                scanned_files.add(file_hash)
            
            print(f"\nScanning file: {path}")
            if api_key:
                result = check_file_with_virustotal(path, api_key)
            return
        
        print(f"\nScanning directory: {path}")
        for root, dirs, files in os.walk(path):
            for f in files:
                file_full_path = os.path.join(root, f)
                file_hash = calculate_file_hash(file_full_path)
                
                if not file_hash:
                    continue
                
                if file_hash in scanned_files:
                    print(f"File already scanned: {file_full_path}")
                    continue
                
                scanned_files.add(file_hash)
                print(f"Scanning: {file_full_path}")
                
                if api_key:
                    result = check_file_with_virustotal(file_full_path, api_key)

    except Exception as e:
        print(f"Error scanning {path}: {e}")

class DownloadHandler(FileSystemEventHandler):
    """Handler for monitoring download folder"""
    def __init__(self, api_key):
        self.api_key = api_key
    
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            print(f"\nNew file detected in Downloads: {file_path}")
            scan_file_path(file_path, self.api_key)

def monitor_downloads(api_key=None):
    """Start monitoring the downloads folder for new files"""
    downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
    event_handler = DownloadHandler(api_key)
    observer = Observer()
    observer.schedule(event_handler, downloads_path, recursive=True)
    observer.start()
    print(f"Started monitoring downloads folder: {downloads_path}")
    return observer

def interactive_scan_loop():
    """Main interactive loop for user-initiated scans"""
    print("\nFile Scanner AntiVirus")
    print("----------------------")
    
    api_key = input("Enter your VirusTotal API key (or press Enter to skip): ").strip()
    if not api_key:
        print("VirusTotal scanning will be disabled")
    
    # Start monitoring downloads folder
    observer = monitor_downloads(api_key if api_key else None)
    
    try:
        while True:
            path = input("\nEnter file or directory path to scan (or 'quit' to exit): ").strip()
            if path.lower() == 'quit':
                break
            
            if os.path.exists(path):
                scan_file_path(path, api_key if api_key else None)
                print("\nScanning completed.")
            else:
                print("Error: Path does not exist. Please try again.")
    except KeyboardInterrupt:
        print("\nReceived interrupt signal.")
    finally:
        observer.stop()
        observer.join()
        print("Stopped downloads monitoring.")
        print("Total files scanned:", len(scanned_files))

if __name__ == "__main__":
    interactive_scan_loop()