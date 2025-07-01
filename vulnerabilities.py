from typing import Dict, List, Any

class VulnerabilityChecker:
    """Vérifie les vulnérabilités basées sur le service, la bannière et la configuration SSL."""
    def check_vulnerabilities(self, ip: str, port: int, service: str, banner: str, ssl_info: Dict[str, Any]) -> List[Dict]:
        """Vérifie les vulnérabilités connues en fonction des informations recueillies."""
        vulnerabilities = []
        
        # Vulnérabilité basée sur le service/la bannière
        if "Apache" in service and "2.4.29" in banner:
            vulnerabilities.append({
                "cve": "CVE-2019-0211",
                "severity": "High",
                "description": "In Apache HTTP Server 2.4 releases 2.4.17 to 2.4.38, a flaw in the mod_auth_digest component could allow a user with valid credentials to authenticate using another username, bypassing security controls.",
                "remediation": "Upgrade to Apache HTTP Server 2.4.39 or later."
            })

        # Vulnérabilité basée sur la configuration SSL
        if ssl_info and "protocol" in ssl_info:
            protocol = ssl_info["protocol"]
            if protocol in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
                vulnerabilities.append({
                    "cve": "CVE-2014-3566" if protocol == "SSLv3" else "N/A",
                    "severity": "Medium",
                    "description": f"The service supports {protocol}, which is an outdated and insecure protocol. This makes it vulnerable to attacks like POODLE (for SSLv3) or BEAST/CRIME (for TLS 1.0).",
                    "remediation": f"Disable {protocol} and enable TLS 1.2 and TLS 1.3."
                })

        if not vulnerabilities:
            return [{"message": "No specific vulnerabilities found based on the provided information."}]
            
        return vulnerabilities
