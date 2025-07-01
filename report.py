import json
from typing import Dict, List, Any
from datetime import datetime

class AdvancedJSONEncoder(json.JSONEncoder):
    """Encodeur JSON personnalisé pour gérer les types de données complexes."""
    def default(self, o: Any) -> Any:
        if isinstance(o, bytes):
            return o.decode(errors='replace')
        if isinstance(o, (set, frozenset)):
            return list(o)
        if hasattr(o, '__dict__'):
            return o.__dict__
        return super().default(o)

class ReportGenerator:
    """Génère et affiche des rapports de scan détaillés et lisibles par l'homme."""
    def __init__(self, output_file: str):
        self.output_file = output_file

    def generate_json_report(self, results: List[Dict]) -> None:
        """Génère un rapport JSON structuré et détaillé."""
        report = {
            "scan_summary": {
                "timestamp": datetime.now().isoformat(),
                "total_ports_scanned": len(results),
                "ports_open": len([r for r in results if r.get("status") == "open"]),
            },
            "scan_results": results
        }
        
        with open(self.output_file, "w", encoding='utf-8') as f:
            json.dump(report, f, indent=4, cls=AdvancedJSONEncoder, ensure_ascii=False)

    def display_text_report(self, results: List[Dict]) -> None:
        """Affiche un rapport textuel lisible."""
        for result in results:
            print(f"\n=== Scan Report for {result.get('ip', 'N/A')}:{result.get('port', 'N/A')} ({result.get('domain', 'No domain')}) ===")
            print(f"Timestamp: {result.get('timestamp', 'N/A')}")
            if result.get("error"):
                print(f"Error: {result['error']}")
                print("=" * 50)
                continue
            
            scan_details = result.get("results", {})
            print(f"Status: {scan_details.get('status', 'unknown')}")
            
            service = scan_details.get("service", {})
            print(f"Service: {service.get('service', 'unknown')} (Protocol: {service.get('protocol', 'N/A')}, Confidence: {service.get('confidence', 'N/A')})")
            
            waf = scan_details.get("waf", {})
            if waf.get("success"):
                print(f"WAF Detected: {waf.get('waf_name', 'Unknown')}")
                print(f"  Bypass Successful: {waf.get('bypassed', False)}")
                if waf.get('bypassed'):
                    print(f"  Bypass Strategy: {waf.get('bypass_strategy', 'N/A')}")

            # Displaying details of advanced bypass attempts
            if 'bypass_attempts' in scan_details:
                print("\n--- Advanced Bypass Attempts ---")
                for attempt in scan_details['bypass_attempts'].get('details', {}).get('attempts', []):
                    print(f"  Strategy: {attempt.get('strategy_used', 'N/A')}")
                    print(f"    Status Code: {attempt.get('status_code', 'N/A')}")
                    if attempt.get('error'):
                        print(f"    Error: {attempt['error']}")
            print("=" * 50)