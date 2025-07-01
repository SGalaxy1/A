# network_tool/state.py
from concurrent.futures import ThreadPoolExecutor
import ctypes
import os
import logging

logger = logging.getLogger(__name__)

def is_admin() -> bool:
    """Vérifie si le script est exécuté avec des privilèges administratifs."""
    try:
        if os.name == 'nt':  # Windows
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/Unix
            return os.geteuid() == 0
    except Exception as e:
        logger.error(f"Erreur lors de la vérification des privilèges administratifs : {str(e)}")
        return False

class ScannerState:
    """Classe pour gérer l'état du scanner réseau."""
    def __init__(self):
        self.is_admin = is_admin()
        self.executor = ThreadPoolExecutor(max_workers=1) if self.is_admin else None
        logger.info(f"ScannerState initialisé. Privilèges administratifs : {self.is_admin}")

    def cleanup(self) -> None:
        """Nettoie les ressources de l'état, comme l'exécuteur."""
        if self.executor:
            self.executor.shutdown(wait=True)
            logger.info("ThreadPoolExecutor arrêté avec succès")
            self.executor = None