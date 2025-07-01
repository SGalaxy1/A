from typing import List, Optional

class ScannerConfig:
    """Configuration pour le scanner réseau."""
    def __init__(
        self,
        target_ips: Optional[List[str]] = None,
        domains: Optional[List[str]] = None,
        ports: Optional[List[int]] = None,
        proxies: Optional[List[str]] = None,
        max_concurrent_scans: Optional[int] = None,
        timeout: Optional[float] = None,
        output_file: Optional[str] = None,
        lstm_enabled: Optional[bool] = None,
        zombie_ips: Optional[List[str]] = None,
        use_idle_scan: Optional[bool] = False,
        use_decoy_scan: Optional[bool] = False,
        decoys: Optional[List[str]] = None,
        use_fragmented_scan: Optional[bool] = False
    ):
        self.target_ips: List[str] = target_ips or []
        self.domains: List[str] = domains or []
        self.ports: List[int] = ports or []
        self.proxies: List[str] = proxies or []
        self.max_concurrent_scans: int = max_concurrent_scans or 50
        self.timeout: float = timeout or 5.0
        self.output_file: str = output_file or "scan_report.json"
        self.lstm_enabled: bool = lstm_enabled if lstm_enabled is not None else False
        self.zombie_ips: List[str] = zombie_ips or []
        self.use_idle_scan: bool = use_idle_scan if use_idle_scan is not None else False
        self.use_decoy_scan: bool = use_decoy_scan if use_decoy_scan is not None else False
        self.decoys: List[str] = decoys or []
        self.use_fragmented_scan: bool = use_fragmented_scan if use_fragmented_scan is not None else False