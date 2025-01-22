import os
from typing import Dict, List, Tuple
import ipaddress

class ZeekLogAnalyzer:
    def __init__(self):
        self.merlin_fingerprints = ["ISishIH", "IShisIH"]
        self.total_datasets = 0
        self.total_entries = 0
        self.merlin_detections = []
        
    def parse_log_file(self, filepath: str) -> List[Dict]:
        entries = []
        headers = []
        
        with open(filepath, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    if line.startswith('#fields'):
                        headers = line.strip().split('\t')[1:]
                    continue
                    
                values = line.strip().split('\t')
                if len(values) == len(headers):
                    entry = dict(zip(headers, values))
                    entries.append(entry)
                    
        return entries

    def analyze_file(self, filepath: str) -> Dict:
        entries = self.parse_log_file(filepath)
        self.total_entries += len(entries)

        merlin_instances = []
        for entry in entries:
            if any(fingerprint in entry['history'] for fingerprint in self.merlin_fingerprints):
                try:
                    ip = entry.get('id.resp_h', 'Unknown IP')
                    if ipaddress.ip_address(ip):
                        merlin_instances.append(ip)
                except ValueError:
                    continue
                    
        return {
            'total_connections': len(entries),
            'merlin_instances': merlin_instances
        }

    def format_results(self, label: str, results: Dict) -> str:
        output = [f"\nLABEL: {label}"]
        output.append(f"* Total amount of QUIC connections in set: {results['total_connections']}")
        
        if results['merlin_instances']:
            for ip in results['merlin_instances']:
                output.append(f"* 1 instance of Merlin fingerprint detected in dataset to target {ip}")
        else:
            output.append("* No instances of Merlin fingerprint detected")
            
        return "\n".join(output)

    def format_final_results(self) -> str:
        output = ["\nFINAL RESULTS"]
        output.append(f"* Total amount of datasets: {self.total_datasets}")
        output.append(f"* Total amount of QUIC entries: {self.total_entries}")
        
        if self.merlin_detections:
            output.append(f"* Total Merlin fingerprints detected: {len(self.merlin_detections)}")
            output.append("  Detected in following IPs:")
            for ip in sorted(set(self.merlin_detections)):
                output.append(f"  - {ip}")
        else:
            output.append("* No Merlin fingerprints detected in any dataset")
                
        return "\n".join(output)

def main():
    analyzer = ZeekLogAnalyzer()
    input_dir = "./input"
    
    if not os.path.exists(input_dir):
        print(f"Error: Input directory '{input_dir}' does not exist!")
        return
        
    all_results = []
    
    for filename in os.listdir(input_dir):
        if filename.endswith('.log'):
            filepath = os.path.join(input_dir, filename)
            label = os.path.splitext(filename)[0]
            
            try:
                results = analyzer.analyze_file(filepath)
                analyzer.total_datasets += 1
                analyzer.merlin_detections.extend(results['merlin_instances'])
                
                formatted_results = analyzer.format_results(label, results)
                all_results.append(formatted_results)
                print(formatted_results)
                
            except Exception as e:
                print(f"Error processing file {filename}: {str(e)}")
                continue
    
    final_results = analyzer.format_final_results()
    all_results.append(final_results)
    print(final_results)
    
    with open('results.txt', 'w') as f:
        f.write("\n".join(all_results))

if __name__ == "__main__":
    main()