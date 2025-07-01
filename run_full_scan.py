import asyncio
import logging
from scanner import NetworkScanner
from config import ScannerConfig

# Configure logging for better visibility
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

async def main():
    """
    Configure et exécute un scan réseau complet en utilisant toutes les fonctions
    et stratégies de contournement WAF de la classe NetworkScanner,
    y compris les techniques NetGhost et Chameleon.
    """
    logger.info("Démarrage de la démonstration du scan complet avec NetGhost et Chameleon.")

    # Configuration du scanner pour activer toutes les stratégies
    config = ScannerConfig(
        target_ips=["127.0.0.1"],  # Cible locale pour la démonstration
        ports=[80],               # Port HTTP standard
        timeout=10.0,             # Timeout pour les requêtes
        use_idle_scan=True,       # Active le scan Idle (NetGhost)
        zombie_ips=["192.168.1.100", "192.168.1.101"], # IPs zombies factices pour Idle Scan
        use_decoy_scan=True,      # Active le scan Decoy (NetGhost)
        decoys=["192.168.1.200", "192.168.1.201", "192.168.1.202"], # IPs leurres factices pour Decoy Scan
        use_fragmented_scan=True  # Active le scan fragmenté (NetGhost)
    )

    scanner = NetworkScanner(config)

    # Exécution du scan sur la cible et le port spécifiés
    target_ip = config.target_ips[0]
    target_port = config.ports[0]

    logger.info(f"Lancement du scan sur {target_ip}:{target_port} avec les stratégies activées.")
    
    # La méthode scan_port orchestre l'appel des différentes fonctions
    # NetGhost (Idle, Decoy, Fragmented) et Chameleon (HTTP Header Mimicry, WAF Bypass)
    # en fonction de la configuration et des résultats intermédiaires.
    scan_result = await scanner.scan_port(target_ip, target_port)

    logger.info(f"Résultats du scan pour {target_ip}:{target_port}:")
    for key, value in scan_result.items():
        if key == "service_info" and "tcp_connect" in value:
            # Éviter d'afficher l'objet Scapy sérialisé complet pour la lisibilité
            display_value = value.copy()
            if "response" in display_value["tcp_connect"]:
                display_value["tcp_connect"]["response"] = "Scapy Packet (serialized)"
            logger.info(f"  {key}: {display_value}")
        elif key == "stealth_results":
            logger.info(f"  {key}:")
            for stealth_method, stealth_detail in value.items():
                logger.info(f"    {stealth_method}: {stealth_detail.get('status', 'N/A')} (Confidence: {stealth_detail.get('confidence', 'N/A')})")
                if stealth_method == "decoy_scan" and "details" in stealth_detail:
                    logger.info(f"      Decoy Scan Details: {stealth_detail['details']}")
        elif key == "waf_detection":
            logger.info(f"  {key}: WAF: {value.get('waf', 'None')}, Confidence: {value.get('confidence', 0)}%")
            if value.get('details'):
                logger.info(f"    WAF Detection Details: {value['details']}")
        elif key == "bypass_attempts":
            logger.info(f"  {key}: Bypassed: {value.get('bypassed', False)}")
            if value.get('successful_attempt'):
                logger.info(f"    Successful Bypass Attempt: {value['successful_attempt'].get('strategy')}")
            if value.get('details') and value['details'].get('attempts'):
                logger.info(f"    Total Bypass Attempts: {len(value['details']['attempts'])}")
        else:
            logger.info(f"  {key}: {value}")

    logger.info("Démonstration du scan complet terminée.")

if __name__ == "__main__":
    # Exécuter la fonction main asynchrone
    asyncio.run(main())
