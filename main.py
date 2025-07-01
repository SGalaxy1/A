import asyncio
import ipaddress
import logging
import re
import json
from typing import List, Optional, Tuple
from config import ScannerConfig
from scanner import NetworkScanner
from report import ReportGenerator

# ANSI escape codes for colors
YELLOW = "\033[93m"
ORANGE = "\033[91m"  # Often bright red, good substitute for orange
RESET = "\033[0m"

def display_banner():
    """Displays the program banner."""
    banner_title = "NetworkSensei Ultra"
    border_char = "*"
    border_length = len(banner_title) + 4
    print(f"{ORANGE}{border_char * border_length}{RESET}")
    print(f"{ORANGE}{border_char} {YELLOW}{banner_title}{ORANGE} {border_char}{RESET}")
    print(f"{ORANGE}{border_char * border_length}{RESET}")
    print()

STANDARD_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("scan.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def validate_domain(domain: str) -> bool:
    if not domain:
        return True
    pattern = r"^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$"
    return bool(re.match(pattern, domain))

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def parse_ports(ports_str: str) -> List[int]:
    ports = set()
    if not ports_str:
        return []
    if '-' in ports_str:
        try:
            start, end = map(int, ports_str.split('-'))
            if 0 < start <= end <= 65535:
                for port in range(start, end + 1):
                    ports.add(port)
        except ValueError:
            print(f"Plage de ports invalide : {ports_str}")
            return []
    else:
        try:
            ports.update(int(p.strip()) for p in ports_str.split(',') if 0 < int(p.strip()) <= 65535)
        except ValueError:
            print(f"Liste de ports invalide : {ports_str}")
            return []
    return sorted(list(ports))

def get_user_input() -> Tuple[Optional[str], List[str], Optional[str], List[int], bool, List[str], bool]:
    ip = input("Entrez l'adresse IP à scanner (ex. 192.168.1.1) : ")
    while not validate_ip(ip):
        print("Adresse IP invalide.")
        ip = input("Entrez l'adresse IP à scanner (ex. 192.168.1.1) : ")

    zombie_ips_str = input("Entrez les adresses IP des zombies pour le scan Idle, séparées par des virgules (optionnel) : ")
    zombie_ips = [z.strip() for z in zombie_ips_str.split(',') if validate_ip(z.strip())]

    domain = input("Entrez le nom de domaine associé (ex. example.com, laissez vide si aucun) : ")
    if domain and not validate_domain(domain):
        print("Nom de domaine invalide. Il sera ignoré.")
        domain = None

    ports_str = input("Entrez les ports à scanner (ex. 80,443 ou 1-1000) : ")
    ports = parse_ports(ports_str)

    use_decoy = input("Activer le Decoy Scan (requiert les privilèges admin) ? (o/n) : ").lower() == 'o'
    decoys = []
    if use_decoy:
        decoys_str = input("Entrez les adresses IP leurres, séparées par des virgules (ex: 1.1.1.1,2.2.2.2) : ")
        decoys = [d.strip() for d in decoys_str.split(',') if validate_ip(d.strip())]

    use_fragmentation = input("Activer le Fragmented Scan (requiert les privilèges admin) ? (o/n) : ").lower() == 'o'

    return ip, zombie_ips, domain, ports, use_decoy, decoys, use_fragmentation

async def main():
    display_banner()
    logger.info("Démarrage du scanner réseau")
    try:
        ip, zombie_ips, domain, user_specified_ports, use_decoy, decoys, use_fragmentation = get_user_input()
        
        if not ip:
            return

        combined_ports = sorted(list(set((user_specified_ports or []) + STANDARD_PORTS)))

        config = ScannerConfig(
            target_ips=[ip],
            domains=[domain] if domain else [],
            ports=combined_ports,
            proxies=[],
            timeout=2.0,
            zombie_ips=zombie_ips,
            use_idle_scan=bool(zombie_ips),
            use_decoy_scan=use_decoy,
            decoys=decoys,
            use_fragmented_scan=use_fragmentation
        )

        scanner = NetworkScanner(config)
        report_generator = ReportGenerator("scan_report.json")

        logger.info(f"Lancement du scan symbiotique sur {ip}.")
        scan_results = await scanner.symbiotic_scan(target=ip, ports=combined_ports, domain=domain)

        logger.info("Génération du rapport")
        report_generator.generate_json_report(scan_results.get("scan_details", []))
        
        # Display a summary in the console
        report_generator.display_text_report(scan_results.get("scan_details", []))

        logger.info("Scan terminé avec succès. Rapport enregistré dans scan_report.json")

    except Exception as e:
        logger.error(f"Erreur lors de l'exécution du scan : {str(e)}", exc_info=True)
        print(f"Une erreur s'est produite : {str(e)}. Consultez scan.log pour plus de détails.")

if __name__ == "__main__":
    asyncio.run(main())
