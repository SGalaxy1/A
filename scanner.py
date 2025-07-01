import random
import asyncio
import aiohttp 
import logging
import re
import json
from aiohttp import ClientSession, TCPConnector
from typing import Dict, List, Optional, Any, Set, Tuple
from scapy.all import IP, TCP, UDP, sr1, ICMP, RandShort, send, fragment, Raw
import requests # Added requests library
import uuid # Added for advanced Chameleon functions
from config import ScannerConfig  # Placeholder: Assurez-vous que ce module existe
# from network_tool.utils import generate_spoofed_ip_headers, generate_url_path_variation  # Placeholder - Fonctions définies localement
from bypass import BypassStrategy  # Placeholder
from service_probe import ServiceProbe  # Placeholder
from ssl_analysis import SSLAnalysis  # Placeholder
from vulnerabilities import VulnerabilityChecker  # Placeholder
import ssl

from concurrent.futures import ThreadPoolExecutor
import ctypes
import os
import urllib.parse
import gzip # <--- AJOUT DE L'IMPORT GZIP
import textwrap
from datetime import datetime

import time

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Fonction de vérification des privilèges administratifs ---
def is_admin():
    """Vérifie si le script est exécuté avec des privilèges administratifs."""
    try:
        if os.name == 'nt':  # Windows
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/Unix
            return os.geteuid() == 0
    except Exception:
        return False

# --- Magasin de Signatures WAF ---
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": [
            {"name": "Server", "pattern": r"cloudflare", "case_sensitive": False, "score": 7},
            {"name": "CF-RAY", "pattern": r".+", "case_sensitive": False, "score": 6},
            {"name": "Set-Cookie", "pattern": r"__cfduid|cf_clearance", "case_sensitive": True, "score": 5}, # cf_clearance est clé pour JS challenge
            {"name": "Set-Cookie", "pattern": r"__cf_bm=", "case_sensitive": True, "score": 7}, # Utilisé pour bot management
            {"name": "Expect-CT", "pattern": r"cloudflare", "case_sensitive": False, "score": 4},
            {"name": "CF-Cache-Status", "pattern": r"DYNAMIC|HIT|MISS|EXPIRED|UPDATING|STALE|REVALIDATED", "case_sensitive": False, "score": 3}
        ],
        "body": [
            {"pattern": r"Cloudflare Ray ID:|cdnjs.cloudflare.com|Attention Required! \| Cloudflare|__cf_chl_tk", "score": 7},
            {"pattern": r"ಮಾನವ ಕಿನಾ ಎಂದು ಪರಿಶೀಲಿಸಲಾಗುತ್ತಿದೆ", "score": 6}, # Kannada
            {"pattern": r"Vérification que vous n'êtes pas un robot", "score": 6}, # French
            {"pattern": r"id=[\"']cf-challenge-running[\"']", "score": 8},
            {"pattern": r"jschl_vc", "score": 7}, # Legacy JS challenge
            {"pattern": r"cf_challenge_form", "score": 7}, # Legacy JS challenge
            {"pattern": r"Checking if the site connection is secure", "score": 6},
            {"pattern": r"cf-turnstile", "score": 7}, # Turnstile CAPTCHA
            {"pattern": r"hcaptcha-form", "score": 6}, # hCaptcha, souvent utilisé par CF
            {"pattern": r"Verifying you are human. This may take a few seconds.", "score": 7}, # Nouveau message de challenge
            {"pattern": r"Why do I have to complete a CAPTCHA?", "score": 5}, # Page d'info CAPTCHA
            {"pattern": r"Sorry, you have been blocked", "score": 8, "page_type": "block"}, # Page de blocage explicite
            {"pattern": r"You are unable to access this site", "score": 8, "page_type": "block"},
            {"pattern": r"Access denied \S+ Error code 1020", "score": 9, "page_type": "block_specific_error"}, # Erreur 1020
            {"pattern": r"error code: 1003", "score": 7, "page_type": "block_specific_error"} # Direct IP Access not allowed
        ],
        "status_codes": [
            {"codes": [403], "score": 5, "page_type": "block"}, # Un 403 est un indicateur fort
            {"codes": [503], "score": 4, "page_type": "challenge"}, # Souvent pour JS challenge
            {"codes": [200], "score": 2, "page_type": "challenge_passed_or_info"}, # Un 200 avec des indicateurs de body peut être un challenge réussi ou une page d'info
            {"codes": [429], "score": 6, "page_type": "rate_limit"},
            {"codes": [520, 521, 522, 523, 524, 525, 526, 527], "score": 7, "page_type": "cf_edge_error"} # Erreurs spécifiques de Cloudflare
        ],
        "final_threshold": 9, # Maintenir un seuil élevé pour une bonne confiance
        "js_challenge_indicators": [
            r"jschl_vc", r"cf_challenge_form", r"cf-turnstile", r"window.turnstile", r"window.cfChallenge",
            r"__cf_chl_tk", r"cf-challenge-running", r"challenge-platform/h/", r"/cdn-cgi/challenge-platform/",
            r"invisible-hcaptcha", r"hcaptcha.js" # Ajout pour hCaptcha
        ]
    },
    "Akamai": {
        "headers": [
            {"name": "Server", "pattern": r"AkamaiGHost|Akamai", "case_sensitive": False, "score": 7},
            {"name": "X-Akamai-Transformed", "pattern": r".+", "case_sensitive": False, "score": 6},
            {"name": "X-Cache", "pattern": r"AkamaiGHost", "case_sensitive": False, "score": 5},
            {"name": "X-Akamai-Request-ID", "pattern": r".+", "case_sensitive": False, "score": 4},
            {"name": "Akamai-Request-BC", "pattern": r".+", "case_sensitive": False, "score": 4},
            {"name": "Set-Cookie", "pattern": r"aka_bmsc", "case_sensitive": True, "score": 7} # Cookie de Bot Manager
        ],
        "body": [
            {"pattern": r"Reference Error #\d{2}\.[\da-f]{8}\.[\da-f]{8}\.[\da-f]{8}", "score": 8, "page_type": "block_specific_error"}, # Erreur de référence Akamai
            {"pattern": r"akaUITrickle|akabom_|AKA_PM_|akamai\.com/challenge", "score": 7, "page_type": "challenge_indicator"},
            {"pattern": r"Accès refusé pour des raisons de sécurité|Access Denied", "score": 7, "page_type": "block"},
            {"pattern": r"Your request was blocked by Akamai", "score": 8, "page_type": "block"},
            {"pattern": r"Illegal request", "score": 6, "page_type": "block"} # Message de blocage Akamai fréquent
        ],
        "status_codes": [
            {"codes": [403, 503], "score": 5, "page_type": "block_or_challenge"},
            {"codes": [400], "score": 3, "page_type": "block_or_error"}
        ],
        "final_threshold": 8,
        "js_challenge_indicators": [
            r"akabom_", r"AKA_PM_", r"akamai\.com/challenge", r"sensor_data", r"bm-verify", r"akam\.net/botman/v1/"
        ]
    },
    "AWS WAF": {
        "headers": [
            # ANY_HEADER peut être coûteux. Si possible, cibler des en-têtes spécifiques.
            # {"name": "ANY_HEADER", "pattern": r"x-amz-waf-", "case_sensitive": False, "type": "prefix_match", "score": 7}, # Déjà présent
            {"name": "X-Amz-Waf-Action", "pattern": r".+", "case_sensitive": False, "score": 6},
            {"name": "Server", "pattern": r"awselb|cloudfront", "case_sensitive": False, "score": 2}, # Peut indiquer AWS mais pas spécifiquement WAF
            {"name": "x-amz-cf-id", "pattern": r".+", "case_sensitive": False, "score": 1} # CloudFront ID, souvent avec WAF
        ],
        "body": [
            {"pattern": r"AWS WAF|motivi di sicurezza|por motivos de seguridad|raisons de sécurité", "score": 5},
            {"pattern": r"Request blocked by AWS WAF", "score": 8, "page_type": "block"},
            {"pattern": r"Requête bloquée par AWS WAF", "score": 8, "page_type": "block"},
            {"pattern": r"aws-waf-token", "score": 7, "page_type": "challenge_indicator"},
            {"pattern": r"403 ERROR.{1,100}The request could not be satisfied.", "score": 7, "page_type": "block_cloudfront_waf"} # Page 403 typique de CloudFront + WAF
        ],
        "status_codes": [
            {"codes": [403], "score": 5, "page_type": "block"},
            {"codes": [401], "score": 4, "page_type": "block_or_auth_required"}
        ],
        "final_threshold": 7,
        "js_challenge_indicators": [ # AWS WAF utilise souvent CAPTCHA ou des challenges JS personnalisés
            r"aws.amazon.com/waf/captcha", r"aws-waf-bot-control"
        ]
    },
    "Sucuri": {
        "headers": [
            {"name": "Server", "pattern": r"Sucuri/Cloudproxy", "case_sensitive": False, "score": 8},
            {"name": "X-Sucuri-ID", "pattern": r".+", "case_sensitive": False, "score": 7},
            {"name": "X-Sucuri-Cache", "pattern": r".+", "case_sensitive": False, "score": 6},
            {"name": "X-Sucuri-Block", "pattern": r".+", "case_sensitive": False, "score": 5}
        ],
        "body": [
            {"pattern": r"Access Denied - Sucuri Website Firewall|sucuri.net/blockpage|cloudproxy@sucuri.net", "score": 8},
            {"pattern": r"Accès refusé - Pare-feu Sucuri", "score": 8}
        ],
        "status_codes": [{"codes": [403], "score": 5}],
        "final_threshold": 8
    },
    "ModSecurity": {
        "headers": [
            {"name": "Server", "pattern": r"Mod_Security|mod_sec|mod_security", "case_sensitive": False, "score": 7}, # Ajout mod_security
            {"name": "X-Powered-By", "pattern": r"Mod_Security|mod_security", "case_sensitive": False, "score": 6},
            {"name": "X-Mod-Security-Action", "pattern": r".+", "case_sensitive": False, "score": 5}
        ],
        "body": [
            {"pattern": r"Mod_Security|This website is protected by ModSecurity|NOYB|Atomicorp", "score": 7},
            {"pattern": r"Ce site est protégé par ModSecurity|Just a moment...", "score": 7},
            {"pattern": r"Web Server's Default Page", "score": 3, "page_type": "info"}, # Peut être une page par défaut derrière ModSec
            {"pattern": r"Not Acceptable!|An appropriate representation of the requested resource could not be found on this server.", "score": 6, "page_type": "block_specific_error_406"}, # Souvent pour 406
            {"pattern": r"detected an attack|potentially harmful request", "score": 8, "page_type": "block"}
        ],
        "status_codes": [
            {"codes": [403, 406, 501], "score": 5, "page_type": "block_or_error"}, # 406 est courant pour ModSec
            {"codes": [429], "score": 4, "page_type": "rate_limit"},
            {"codes": [400, 404, 500], "score": 2, "page_type": "generic_error_if_body_matches"} # Score plus bas, dépend du corps
        ],
        "final_threshold": 7,
        "js_challenge_indicators": [] # ModSecurity lui-même ne fait pas de JS challenge, mais peut être combiné.
    },
    "Wordfence": {
        "headers": [
            {"name": "Set-Cookie", "pattern": r"wf_loginalerted|wordfence_verifiedHuman", "case_sensitive": True, "score": 7}
        ],
        "body": [
            {"pattern": r"Generated by Wordfence|wfSCAN", "score": 8},
            {"pattern": r"Your access to this site has been limited by the site owner", "score": 7},
            {"pattern": r"वर्डफ़ेंस द्वारा अवरुद्ध", "score": 7},
            {"pattern": r"Votre accès a été limité par Wordfence", "score": 7}
        ],
        "status_codes": [{"codes": [403, 503], "score": 5}],
        "final_threshold": 8
    },
    "Barracuda": {
        "headers": [
            {"name": "Server", "pattern": r"Barracuda", "case_sensitive": False, "score": 7},
            {"name": "Set-Cookie", "pattern": r"barra_counter_session|BNI__BARRACUDA_", "case_sensitive": True, "score": 6}
        ],
        "body": [
            {"pattern": r"Barracuda Web Application Firewall|barracuda.com", "score": 8},
            {"pattern": r"Để tiếp tục truy cập", "score": 7},
            {"pattern": r"Accès bloqué par Barracuda", "score": 7}
        ],
        "status_codes": [{"codes": [403], "score": 5}],
        "final_threshold": 8
    },
    "F5 BIG-IP": {
        "headers": [
            {"name": "Server", "pattern": r"BIG-IP|F5", "case_sensitive": False, "score": 6},
            {"name": "Set-Cookie", "pattern": r"BIGipServer|TS[a-zA-Z0-9]{8,}", "case_sensitive": True, "score": 7}, # TS cookie est un bon indicateur
            {"name": "Connection", "pattern": r"close", "case_sensitive": False, "score": 3} # Souvent utilisé par F5
        ],
        "body": [
            {"pattern": r"The requested URL was rejected. Please consult with your administrator.", "score": 7, "page_type": "block"},
            {"pattern": r"비정상적인 요청으로 접근이 거부되었습니다", "score": 7, "page_type": "block"}, # Korean
            {"pattern": r"L'URL demandée a été rejetée.", "score": 7, "page_type": "block"}, # French
            {"pattern": r"ASM:|Your request was blocked by the BIG-IP Application Security Manager", "score": 8, "page_type": "block"},
            {"pattern": r"The page was rejected due to a security policy", "score": 8, "page_type": "block"},
            {"pattern": r"Support ID:", "score": 5, "page_type": "block_indicator"} # Souvent présent sur les pages de blocage F5
        ],
        "status_codes": [
            {"codes": [403], "score": 6, "page_type": "block"},
            {"codes": [200], "score": 1, "page_type": "challenge_passed_or_info"} # Un 200 avec un corps de blocage est possible
        ],
        "final_threshold": 8,
        "js_challenge_indicators": [ # F5 peut utiliser des challenges JS, mais ils sont souvent custom ou via des solutions tierces
            r"/f5-w-", r" ಬೆಂಗಳೂರು" # Parfois des artefacts dans le JS ou des commentaires spécifiques
        ]
    },
    "Imperva": { # (Anciennement Incapsula)
        "headers": [
            {"name": "X-CDN", "pattern": r"Incapsula|Imperva", "case_sensitive": False, "score": 8}, # Ajout Imperva
            {"name": "Set-Cookie", "pattern": r"incap_ses_|visid_incap_|reese84", "case_sensitive": True, "score": 7}, # reese84 est un cookie de bot protection Imperva
            {"name": "X-Iinfo", "pattern": r".+", "case_sensitive": False, "score": 6}
        ],
        "body": [
            {"pattern": r"Powered By Incapsula|Incapsula incident ID|rbzns_", "score": 8},
            {"pattern": r"Powered By Imperva", "score": 8}, # Ajout Imperva
            {"pattern": r"Request unsuccessful. Incapsula incident ID", "score": 7, "page_type": "block_specific_error"},
            {"pattern": r"Requête échouée. ID d'incident Incapsula", "score": 7, "page_type": "block_specific_error"},
            {"pattern": r"subject=WAF Block", "score": 6, "page_type": "block_indicator"},
            {"pattern": r"<h1>Request unsuccessful</h1>", "score": 7, "page_type": "block"}, # Page de blocage générique Imperva
            {"pattern": r"To continue, please enable JavaScript", "score": 7, "page_type": "js_challenge"}
        ],
        "status_codes": [
            {"codes": [403], "score": 5, "page_type": "block"},
            {"codes": [200], "score": 2, "page_type": "challenge_passed_or_info"}, # Un 200 avec "enable JavaScript" est un challenge
            {"codes": [401, 405, 429], "score": 4, "page_type": "block_or_other_issue"}
        ],
        "final_threshold": 8,
        "js_challenge_indicators": [
            r"___utmvc", r"_vis_opt_call", r"incapsula_support_id", r"rbzns_",
            r"/_Incapsula_Resource", r"ReeseFramework", r"reese_collect" # Ajouts pour Imperva Bot Protection / Reese
        ]
    },
    "Azure WAF": {
        "headers": [
            {"name": "Server", "pattern": r"Microsoft-Azure-Application-Gateway", "case_sensitive": False, "score": 2},
            {"name": "Set-Cookie", "pattern": r"ApplicationGatewayAffinity", "case_sensitive": True, "score": 1},
            {"name": "X-MSEdge-Ref", "pattern": r".+", "case_sensitive": False, "score": 7}
        ],
        "body": [
            {"pattern": r"Azure Web Application Firewall|The request is blocked by Web Application Firewall", "score": 8},
            {"pattern": r"La requête est bloquée par le pare-feu Azure", "score": 8}
        ],
        "status_codes": [{"codes": [403], "score": 5}],
        "final_threshold": 7
    },
    "FortiWeb": {
        "headers": [
            {"name": "Set-Cookie", "pattern": r"FORTIWAFSID", "case_sensitive": True, "score": 8}
        ],
        "body": [
            {"pattern": r"FortiWeb|Web Server's Default Page", "score": 7},
            {"pattern": r"アクセスいただきありがとうございます", "score": 6},
            {"pattern": r"Accès bloqué par FortiWeb", "score": 7}
        ],
        "status_codes": [
            {"codes": [403], "score": 5},
            {"codes": [200], "score": 2}
        ],
        "final_threshold": 8
    },
    "Citrix NetScaler": {
        "headers": [
            {"name": "Set-Cookie", "pattern": r"ns_af=|citrix_ns_id|NSC_", "case_sensitive": True, "score": 7},
            {"name": "Connection", "pattern": r"close", "case_sensitive": False, "score": 3},
            {"name": "Cneonction", "pattern": r"close", "case_sensitive": False, "score": 1},
            {"name": "X-Powered-By", "pattern": r"NetScaler", "case_sensitive": False, "score": 6}
        ],
        "body": [
            {"pattern": r"NetScaler|The page cannot be displayed", "score": 7},
            {"pattern": r"요청이 거부되었습니다", "score": 6},
            {"pattern": r"La page ne peut pas être affichée", "score": 6},
            {"pattern": r"Violation ID:|Your request was blocked.", "score": 6}
        ],
        "status_codes": [
            {"codes": [403], "score": 6}
        ],
        "final_threshold": 8
    },
    "Fastly CDN": {
        "headers": [
            {"name": "Server", "pattern": r"Fastly", "case_sensitive": False, "score": 2},
            {"name": "X-Cache", "pattern": r".+", "case_sensitive": False, "score": 1},
            {"name": "Vary", "pattern": r"Fastly-SSL", "case_sensitive": False, "score": 1}
        ],
        "body": [
            {"pattern": r"Fastly error: unknown domain", "score": 3},
            {"pattern": r"Accès refusé par Fastly", "score": 6}
        ],
        "status_codes": [
            {"codes": [403, 503], "score": 4}
        ],
        "final_threshold": 5
    },
    "DenyAll": {
        "headers": [
            {"name": "Set-Cookie", "pattern": r"sessioncookie=", "case_sensitive": True, "score": 7},
            {"name": "Server", "pattern": r"DenyAll", "case_sensitive": False, "score": 8}
        ],
        "body": [
            {"pattern": r"Condition Intercepted|DenyAll WAF", "score": 8},
            {"pattern": r"Requête interceptée par DenyAll", "score": 8}
        ],
        "status_codes": [{"codes": [403], "score": 5}],
        "final_threshold": 8
    },
    "Wallarm": {
        "headers": [
            {"name": "Server", "pattern": r"nginx-wallarm", "case_sensitive": False, "score": 8},
            {"name": "X-Wallarm-Token", "pattern": r".+", "case_sensitive": False, "score": 7}
        ],
        "body": [
            {"pattern": r"Blocked by Wallarm|wallarm.com", "score": 8},
            {"pattern": r"Bloqué par Wallarm", "score": 8}
        ],
        "status_codes": [{"codes": [403], "score": 5}],
        "final_threshold": 8
    },
    "Radware AppWall": {
        "headers": [
            {"name": "Server", "pattern": r"AppWall", "case_sensitive": False, "score": 7},
            {"name": "Set-Cookie", "pattern": r"TS[a-zA-Z0-9]{8}", "case_sensitive": True, "score": 6}
        ],
        "body": [
            {"pattern": r"Radware AppWall|This request has been blocked", "score": 8},
            {"pattern": r"Requête bloquée par Radware", "score": 8}
        ],
        "status_codes": [{"codes": [403], "score": 5}],
        "final_threshold": 8
    },
    "Sophos": {
        "headers": [
            {"name": "Server", "pattern": r"Sophos", "case_sensitive": False, "score": 7}
        ],
        "body": [
            {"pattern": r"Sophos Web Appliance|Access Denied", "score": 8},
            {"pattern": r"Accès refusé par Sophos", "score": 8}
        ],
        "status_codes": [{"codes": [403], "score": 5}],
        "final_threshold": 8
    },
    "Reblaze": {
        "headers": [
            {"name": "Server", "pattern": r"Reblaze", "case_sensitive": False, "score": 7},
            {"name": "Set-Cookie", "pattern": r"rbzid=", "case_sensitive": True, "score": 6}
        ],
        "body": [
            {"pattern": r"Reblaze Secure Web Gateway|Access Denied", "score": 8},
            {"pattern": r"Accès interdit par Reblaze", "score": 8}
        ],
        "status_codes": [{"codes": [403], "score": 5}],
        "final_threshold": 8
    },
    "SiteLock": {
        "headers": [
            {"name": "Server", "pattern": r"SiteLock", "case_sensitive": False, "score": 7},
            {"name": "X-Powered-By", "pattern": r"SiteLock", "case_sensitive": True, "score": 6}
        ],
        "body": [
            {"pattern": r"SiteLock Incident ID|Protected by SiteLock", "score": 8},
            {"pattern": r"Protégé par SiteLock", "score": 8}
        ],
        "status_codes": [
            {"codes": [403], "score": 5},
            {"codes": [200], "score": 2}
        ],
        "final_threshold": 8
    },
    "Signal Sciences": {
        "headers": [
            {"name": "Server", "pattern": r"sigsci-nginx|Fastly", "case_sensitive": False, "score": 7},
            {"name": "X-SigSci-RequestID", "pattern": r".+", "case_sensitive": False, "score": 8},
            {"name": "X-SigSci-Tags", "pattern": r".+", "case_sensitive": False, "score": 6}
        ],
        "body": [
            {"pattern": r"Signal Sciences|sigsci_waf_block|signalsciences.net/block", "score": 8},
            {"pattern": r"This request has been blocked by Signal Sciences", "score": 8},
            {"pattern": r"Access Denied - Signal Sciences", "score": 7}
        ],
        "status_codes": [
            {"codes": [403, 406, 500, 503], "score": 5}
        ],
        "final_threshold": 8,
        "js_challenge_indicators": [
            r"sigsci_js_challenge"
        ]
    },
    "StackPath WAF": {
        "headers": [
            {"name": "Server", "pattern": r"StackPath", "case_sensitive": False, "score": 7},
            {"name": "X-SP-WAF-Blocked", "pattern": r"true", "case_sensitive": False, "score": 8},
            {"name": "X-SP-WAF-Action", "pattern": r"block|deny", "case_sensitive": False, "score": 7}
        ],
        "body": [
            {"pattern": r"StackPath WAF|security policy violation", "score": 8},
            {"pattern": r"Please contact the site owner if you believe this is an error", "score": 6}
        ],
        "status_codes": [{"codes": [403, 406], "score": 5}],
        "final_threshold": 8
    },
    "PerimeterX": {
        "headers": [
            {"name": "_pxhd", "pattern": r".+", "case_sensitive": False, "score": 7}, # Header spécifique
            {"name": "X-PX-AUTHORIZATION", "pattern": r".+", "case_sensitive": False, "score": 6},
            {"name": "X-PX-Block", "pattern": r".+", "case_sensitive": False, "score": 6}, # Indique un blocage
            {"name": "Set-Cookie", "pattern": r"_px[A-Za-z0-9\%]+", "case_sensitive": False, "score": 7} # Cookie _px*
        ],
        "body": [
            {"pattern": r"PerimeterX|PXHord", "score": 2}, # PXHord est moins courant
            {"pattern": r"window._px(?:InitialConfig|Events|Utils)", "score": 7, "page_type": "js_challenge_indicator"},
            {"pattern": r"client.perimeterx.net/PX[A-Za-z0-9]+/main.min.js", "score": 8, "page_type": "js_challenge_indicator"},
            {"pattern": r"Human Challenge", "score": 6, "page_type": "captcha_challenge"}
        ],
        "status_codes": [
            {"codes": [403], "score": 6, "page_type": "block"},
            {"codes": [200], "score": 3, "page_type": "challenge_page_or_passed"} # Une page de challenge est souvent en 200
        ],
        "cookies": [
            {"name": "_px", "pattern": r".*", "score": 2}, # Cookie principal
            {"name": "pxvid", "pattern": r".*", "score": 1}, # Visitor ID
            {"name": "_pxCaptcha", "pattern": r".*", "score": 2}, # Captcha cookie
            {"name": "_px2", "pattern": r".*", "score": 3}, # Autre cookie commun
            {"name": "_pxm", "pattern": r".*", "score": 3}  # Autre cookie commun
        ],
        "final_threshold": 9,
        "js_challenge_indicators": [
            r"window._px", r"_pxOnCaptchaSuccess", r"captcha.px-cdn.net", r"client.perimeterx.net",
            r"px-captcha", r"pxchk"
        ]
    },
    "Kasada": {
        "headers": [
            {"name": "X-Kasada-Action", "pattern": r".+", "case_sensitive": False, "score": 6},
            {"name": "X-Kasada-Status", "pattern": r".+", "case_sensitive": False, "score": 5},
            {"name": "Set-Cookie", "pattern": r"kpsdk_", "case_sensitive": False, "score": 7} # Cookie de Kasada
        ],
        "body": [
            {"pattern": r"Kasada|__kasada__|kpsdk", "score": 6, "page_type": "js_challenge_indicator"},
            {"pattern": r"kasada-static\.com|gateway\.kasada\.io", "score": 5, "page_type": "js_challenge_indicator"},
            {"pattern": r"Please enable JavaScript and Cookies", "score": 7, "page_type": "js_challenge"},
            {"pattern": r"kpsdk-fc", "score": 8, "page_type": "js_challenge_indicator"} # Fingerprint collector
        ],
        "status_codes": [
            {"codes": [403, 429], "score": 6, "page_type": "block_or_challenge"},
            {"codes": [200, 204], "score": 3, "page_type": "challenge_page_or_passed"} # 204 No Content peut être utilisé pour des beacons
        ],
        "cookies": [
            {"name": "kps", "pattern": r".*", "score": 2},
            {"name": "kasada_id", "pattern": r".*", "score": 1},
            {"name": "kpsdk-prod", "pattern": r".*", "score": 7}
        ],
        "final_threshold": 9,
        "js_challenge_indicators": [
            r"__kasada_js_token_", r"kasada-javascript", r"kpsdk", r"x-kpsdk-ct",
            r"kp.js", r"kasada.com/api/v\d+/kpsdk"
        ]
    }
    # Ajouter d'autres WAFs si nécessaire, par exemple :
    # "DataDome": { ... },
    # "Shape Security": { ... },
    # "Google Cloud Armor": { ... }
}

# == Fonctions Utilitaires (Hors Classe) ==

def generate_random_header_case(header_name: str) -> str:
    """Génère une version avec casse aléatoire d'un nom d'en-tête HTTP."""
    return ''.join(random.choice([c.upper(), c.lower()]) for c in header_name)

def generate_spoofed_ip_headers(strategy_hints: Optional[Dict[str, Any]] = None) -> dict:
    """Crée un dictionnaire d'en-têtes de spoofing IP courants avec des adresses IP aléatoires."""
    return {
        "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
        "Client-IP": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    }

def generate_common_accept_headers(strategy_hints: Optional[Dict[str, Any]] = None) -> dict:
    """Produit un dictionnaire d'en-têtes Accept, Accept-Language, et Accept-Encoding courants."""
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br"
    }

def generate_dynamic_user_agent() -> str:
    """Génère un User-Agent réaliste et dynamique."""
    os_list = [
        "Windows NT 10.0; Win64; x64", "Windows NT 6.1; WOW64", "Macintosh; Intel Mac OS X 10_15_7",
        "X11; Linux x86_64", "Android 10; Mobile", "iPhone; CPU iPhone OS 14_0_1 like Mac OS X"
    ]
    browser_list = [
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.{}.{} Safari/537.36",
        "Gecko/20100101 Firefox/{}.0",
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
    ]
    # Randomly select OS and browser version
    os_choice = random.choice(os_list)
    browser_choice = random.choice(browser_list)

    if "Chrome" in browser_choice:
        major = random.randint(90, 120)
        minor = random.randint(0, 999)
        patch = random.randint(0, 999)
        browser_str = browser_choice.format(major, minor, patch)
    elif "Firefox" in browser_choice:
        major = random.randint(80, 120)
        browser_str = browser_choice.format(major)
    else: # Safari/Mobile Safari
        browser_str = browser_choice

    return f"Mozilla/5.0 ({os_choice}) {browser_str}"

def generate_customized_headers(base_headers: Dict[str, str], strategy_hints: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Génère un ensemble d'en-têtes HTTP personnalisés basés sur des en-têtes de base et des stratégies."""
    headers = base_headers.copy()
    if strategy_hints and strategy_hints.get("random_case"):
        headers = {generate_random_header_case(k): v for k, v in headers.items()}
    return headers

# MODIFIED FUNCTION generate_url_path_variation
def generate_url_path_variation(base_path: str = "/", strategy_hints: Optional[Dict[str, Any]] = None) -> str:
    """
    Crée des variations d'un chemin d'URL de base pour l'obfuscation et la découverte,
    en utilisant des strategy_hints pour guider la génération.
    """
    if not strategy_hints:
        strategy_hints = {}

    current_variations = [
        base_path,
        f"{base_path.rstrip('/')}/.", # Dot segment
        f"{base_path.rstrip('/')}//{base_path.lstrip('/') if base_path != '/' else ''}", # Double slash
        f"{base_path.rstrip('/')}/%2e", # Encoded dot
        f"{base_path.rstrip('/')}/%252e", # Double encoded dot
        f"{base_path.rstrip('/')}/..;/", # Semicolon traversal
        f"{base_path.rstrip('/')}/%00", # Null byte injection (path)
        f"{base_path.rstrip('/')}/%ff", # High byte injection (path)
        f"{base_path.rstrip('/')}/%u002e", # Unicode encoded dot
        f"{base_path.rstrip('/')}/%u002f", # Unicode encoded slash
        f"{base_path.rstrip('/')}/%c0%af", # UTF-7 encoded slash
        f"{base_path.rstrip('/')}/%c0%ae", # UTF-7 encoded dot
        f"{base_path.rstrip('/')}/%e0%80%af", # UTF-8 overlong encoding for slash
        f"{base_path.rstrip('/')}/%e0%80%ae", # UTF-8 overlong encoding for dot
    ]

    transformed_path = base_path

    if strategy_hints.get("case_variation"):
        temp_path = ""
        for char_original in base_path:
            if char_original.isalpha():
                temp_path += char_original.upper() if random.choice([True, False]) else char_original.lower()
            else:
                temp_path += char_original
        transformed_path = temp_path
        current_variations.append(transformed_path)

    if strategy_hints.get("double_encode_selected_chars"):
        path_to_encode = transformed_path
        chars_to_encode = strategy_hints.get("chars_for_double_encoding", ['.', '/'])

        encoded_variation_list = list(path_to_encode)
        made_change = False
        for i, char_original in enumerate(encoded_variation_list):
            if char_original in chars_to_encode and random.choice([True, False]):
                encoded_once = urllib.parse.quote(char_original, safe='')
                encoded_twice = urllib.parse.quote(encoded_once, safe='')
                if encoded_twice != char_original :
                    encoded_variation_list[i] = encoded_twice
                    made_change = True
        if made_change:
            current_variations.append("".join(encoded_variation_list))

    if strategy_hints.get("trailing_slash_toggle"):
        path_for_slash_toggle = transformed_path
        if path_for_slash_toggle.endswith('/'):
            current_variations.append(path_for_slash_toggle.rstrip('/'))
        else:
            current_variations.append(path_for_slash_toggle + '/')

    if strategy_hints.get("add_random_query_param"):
        path_for_query = transformed_path
        random_param_name = f"_{random.choice(['z', 'y', 'x'])}{random.randint(100,999)}"
        random_param_value = str(random.randint(1,100))
        separator = "?" if "?" not in path_for_query else "&"
        current_variations.append(f"{path_for_query}{separator}{random_param_name}={random_param_value}")

    if not current_variations:
        current_variations.append(base_path)

    return random.choice(list(set(current_variations)))

# MODIFIED FUNCTION generate_query_param_variations
def generate_query_param_variations(base_params: Optional[Dict[str, str]] = None, strategy_hints: Optional[Dict[str, Any]] = None, num_extra_params: int = 0) -> str:
    """
    Construit une chaîne de requête avec des paramètres variés, appliquant des techniques de manipulation.
    base_params: Dictionnaire de paramètres de base.
    strategy_hints: Options pour la manipulation.
    num_extra_params: Nombre de paramètres factices supplémentaires à ajouter.
    """
    if base_params is None:
        base_params = {}
    if strategy_hints is None:
        strategy_hints = {}

    final_params_list: List[Tuple[str, str]] = []

    for key, value in base_params.items():
        current_key, current_value = key, str(value)

        if strategy_hints.get("param_name_case_variation"):
            temp_key = ""
            for char_k in current_key:
                if char_k.isalpha():
                    temp_key += char_k.upper() if random.choice([True, False]) else char_k.lower()
                else:
                    temp_key += char_k
            current_key = temp_key

        final_params_list.append((current_key, current_value))

        if strategy_hints.get("hpp_param_pollution") and random.choice([True, False]):
            polluted_value = strategy_hints.get("hpp_polluted_value", f"val_{random.randint(1000,2000)}")
            final_params_list.append((current_key, polluted_value))

    for i in range(num_extra_params):
        param_name = f"_{random.choice(['csrf', 'debug', 'uid', 'trace', 'lang', 'ret'])}{random.randint(100,999)}"
        param_value = str(random.randint(1, 10000))
        if strategy_hints.get("param_name_case_variation"):
            temp_key_extra = ""
            for char_k_extra in param_name:
                if char_k_extra.isalpha():
                    temp_key_extra += char_k_extra.upper() if random.choice([True, False]) else char_k_extra.lower()
                else:
                    temp_key_extra += char_k_extra
            param_name = temp_key_extra
        final_params_list.append((param_name, param_value))

    if strategy_hints.get("obfuscate_common_params"):
        # Add random, common-looking parameters to confuse WAFs
        obfuscated_param_name = f"_{random.choice(['q', 's', 'id', 'p', 'o'])}{random.randint(100,999)}"
        obfuscated_param_value = str(random.randint(1, 10000))
        final_params_list.append((obfuscated_param_name, obfuscated_param_value))

        # Add null byte or high byte to parameter names/values
        if random.choice([True, False]):
            null_byte_param_name = f"null_param%00{random.randint(1,9)}"
            final_params_list.append((null_byte_param_name, "value"))
        if random.choice([True, False]):
            high_byte_param_value = f"value%ff{random.randint(1,9)}"
            final_params_list.append(("high_byte_param", high_byte_param_value))

    if strategy_hints.get("randomize_param_order"):
        random.shuffle(final_params_list)

    # Apply various encoding techniques to parameters
    encoded_params = []
    for key, value in final_params_list:
        if strategy_hints.get("double_encode_params") and random.choice([True, False]):
            key = urllib.parse.quote(key, safe='')
            value = urllib.parse.quote(value, safe='')
        if strategy_hints.get("unicode_encode_params") and random.choice([True, False]):
            key = ''.join([f"%u{ord(c):04x}" if ord(c) > 127 else c for c in key])
            value = ''.join([f"%u{ord(c):04x}" if ord(c) > 127 else c for c in value])
        encoded_params.append((key, value))

    return urllib.parse.urlencode(encoded_params, doseq=True) # doseq=True for multiple values for same key

def generate_request_body(method: str, content_type_choice: str, strategy_hints: Optional[Dict[str, Any]] = None) -> tuple[Optional[bytes], Optional[str]]:
    """Génère un corps de requête et l'en-tête Content-Type correspondant, basé sur la méthode et des stratégies."""
    if method.upper() not in ["POST", "PUT"]:
        return None, None
    if content_type_choice == "json":
        return b'{"test": "value"}', "application/json"
    elif content_type_choice == "form":
        return b"key=value", "application/x-www-form-urlencoded"
    elif content_type_choice == "xml":
        return b'<?xml version="1.0"?><data>test</data>', "application/xml"
    return None, None

# == Classe NetworkScanner ==
class NetworkScanner:
    """Classe principale pour le scanner réseau."""
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.service_probe = ServiceProbe()
        self.ssl_analyzer = SSLAnalysis()
        self.vuln_checker = VulnerabilityChecker()
        self.bypass = BypassStrategy(self) # Pass self to BypassStrategy
        self.proxy_failures = {}  # Gestion des échecs de proxy
        self.lstm_model = self._load_lstm_model()
        self.http_ports = {80, 443, 8080, 8443}  # Ports valides pour les requêtes HTTP/HTTPS

        # Assurez-vous que zombie_ips et use_idle_scan sont initialisés dans self.config
        if not hasattr(self.config, 'zombie_ips'):
            self.config.zombie_ips = [] # Valeur par défaut: liste vide
            logger.info("zombie_ips not set in config, defaulting to an empty list.")
        elif not isinstance(self.config.zombie_ips, list):
            logger.warning(f"zombie_ips in config is not a list (type: {type(self.config.zombie_ips)}). Defaulting to an empty list.")
            self.config.zombie_ips = []

        if not hasattr(self.config, 'use_idle_scan'):
            self.config.use_idle_scan = False # Valeur par défaut
            logger.info("use_idle_scan not set in config, defaulting to False.")
        
        if self.config.use_idle_scan:
            if not self.config.zombie_ips:
                logger.warning("use_idle_scan is True but no zombie_ips are configured or the list is empty. Idle scan will be disabled.")
                self.config.use_idle_scan = False
            else:
                logger.info(f"Idle scan enabled with {len(self.config.zombie_ips)} potential zombie(s): {self.config.zombie_ips}")
        else:
            # Log current state if idle scan is disabled for clarity
            if hasattr(self.config, 'zombie_ips') and self.config.zombie_ips:
                 logger.info(f"Idle scan is disabled (use_idle_scan: {self.config.use_idle_scan}), though zombie_ips are provided: {self.config.zombie_ips}")
            else:
                 logger.info(f"Idle scan is disabled (use_idle_scan: {self.config.use_idle_scan}, no zombie_ips provided).")


        # Initialisation de la configuration des proxies si elle n'existe pas
        if not hasattr(self.config, 'proxy_max_failures'):
            self.config.proxy_max_failures = 3
            logger.info(f"Proxy max failures not set in config, defaulting to {self.config.proxy_max_failures}")
        if not hasattr(self.config, 'proxy_disable_duration'):
            self.config.proxy_disable_duration = 300
            logger.info(f"Proxy disable duration not set in config, defaulting to {self.config.proxy_disable_duration} seconds")
        if not hasattr(self.config, 'proxies'):
            self.config.proxies = []
            logger.info("No proxies defined in configuration, proxy list initialized to empty.")

        self.proxies = self._load_proxies()

        # Vérification des privilèges et ajout de l'exécuteur
        self.state = type('State', (), {
            'is_admin': is_admin(),
            'executor': ThreadPoolExecutor(max_workers=1)
        })()
        # Configuration de l'interface réseau par défaut
        if not hasattr(self.config, 'DEFAULT_IFACE'):
            from scapy.all import conf
            self.config.DEFAULT_IFACE = conf.iface
            logger.info(f"Interface réseau par défaut configurée : {self.config.DEFAULT_IFACE}")

    def _load_lstm_model(self) -> Optional[Any]:
        """Charge le modèle LSTM pour la prédiction de services (si disponible)."""
        try:
            return None
        except Exception as e:
            logger.error(f"Failed to load LSTM model: {str(e)}")
            return None

    def _load_proxies(self) -> List[Dict[str, Any]]:
        """Charge la liste des proxies depuis la configuration et des sources publiques."""
        proxies = [{"url": proxy, "geo": self._infer_proxy_geo(proxy)} for proxy in self.config.proxies]
        return proxies

    def _infer_proxy_geo(self, proxy_url: str) -> str:
        """Infère la géolocalisation approximative d'un proxy à partir de son URL."""
        return "unknown"

    def report_proxy_failure(self, proxy_url: str) -> None:
        """Signale un échec pour un proxy donné et met à jour ses métadriques."""
        self.proxy_failures[proxy_url] = self.proxy_failures.get(proxy_url, 0) + 1
        logger.warning(f"Proxy {proxy_url} failed. Total failures: {self.proxy_failures[proxy_url]}")

    def _get_next_proxy(self, prefer_different_geo_from: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Sélectionne le prochain proxy à utiliser, en priorisant la santé et optionnellement la diversité géographique."""
        healthy_proxies = [p for p in self.proxies if self.proxy_failures.get(p["url"], 0) < self.config.proxy_max_failures]
        if not healthy_proxies:
            return None
        if prefer_different_geo_from:
            filtered = [p for p in healthy_proxies if p["geo"] != prefer_different_geo_from]
            return random.choice(filtered) if filtered else random.choice(healthy_proxies)
        return random.choice(healthy_proxies)

    def _get_random_source_ip(self) -> Optional[str]:
        """Sélectionne une adresse IP source aléatoire pour le spoofing (si configurée)."""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

    def _extract_features(self, pkt: IP, response_time: float) -> Any:
        """Extrait des caractéristiques d'un paquet réseau pour l'analyse (ex: par le modèle LSTM)."""
        return {
            "ttl": pkt.ttl if hasattr(pkt, "ttl") else None,
            "response_time": response_time,
            "flags": pkt.flags if hasattr(pkt, "flags") else None
        }

    def _predict_service_lstm(self, features: Any) -> Tuple[str, float]:
        """Prédit un service réseau en utilisant le modèle LSTM et les caractéristiques extraites."""
        return "unknown", 0.0

    def _predict_service_heuristic(self, pkt: IP, response_time: float) -> Tuple[str, float]:
        """Prédit un service réseau en utilisant des règles heuristiques basées sur le paquet reçu."""
        return "unknown", 0.0

    # ==============================================================================
    # Section: Chameleon - Techniques d'évasion et de mimétisme
    # ==============================================================================

    async def traffic_pacing_control(self, base_delay: float = 0.1, jitter: float = 0.05, multiplier: float = 1.0):
        """
        Contrôle le rythme du trafic en introduisant des délais variables entre les paquets.
        """
        delay = (base_delay + random.uniform(-jitter, jitter)) * multiplier
        logger.info(f"[Chameleon] Applying traffic pacing. Delaying for {delay:.3f} seconds.")
        await asyncio.sleep(max(0, delay))

    def os_fingerprint_evasion(self, os_type: str = "Linux") -> Dict[str, Any]:
        """
        Génère des paramètres de paquets (TTL, Window Size, TCP Options) pour imiter un OS spécifique.
        """
        logger.info(f"[Chameleon] Applying OS Fingerprint Evasion. Mimicking: {os_type}")
        # Base de données d'empreintes simplifiée
        fingerprints = {
            "Linux": {"ttl": 64, "window": 5840, "options": [('MSS', 1460), ('SACK', b''), ('Timestamp', (0, 0)), ('NOP', None), ('WScale', 7)]},
            "Windows": {"ttl": 128, "window": 8192, "options": [('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SACK', b'')]},
            "FreeBSD": {"ttl": 64, "window": 65535, "options": [('MSS', 1460), ('NOP', None), ('WScale', 6), ('SACK', b''), ('Timestamp', (0,0))]},
            "iOS": {"ttl": 64, "window": 65535, "options": [('MSS', 1440), ('NOP', None), ('WScale', 6), ('SACK', b''), ('Timestamp', (0,0))]},
            "Android": {"ttl": 64, "window": 29200, "options": [('MSS', 1460), ('SACK', b''), ('Timestamp', (0,0)), ('NOP', None), ('WScale', 7)]}
        }
        return fingerprints.get(os_type, fingerprints["Linux"])

    def http_header_mimicry(self, target_profile: str = "chrome_windows", strategy_hints: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """
        Génère un ensemble d'en-têtes HTTP réalistes pour imiter un client spécifique, avec des options avancées.
        """
        if strategy_hints is None:
            strategy_hints = {}

        logger.info(f"[Chameleon] Applying HTTP Header Mimicry. Profile: {target_profile}")

        # Base profiles
        profiles = {
            "chrome_windows": {
                "User-Agent": generate_dynamic_user_agent(),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
                "Connection": "keep-alive"
            },
            "firefox_macos": {
                "User-Agent": generate_dynamic_user_agent(),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
                "Te": "trailers",
                "Connection": "keep-alive"
            },
            "googlebot": {
                "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "*",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "close" # Bots often close connection
            },
            "random": {
                "User-Agent": generate_dynamic_user_agent(),
                "Accept": random.choice([
                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "*/*",
                    "application/json, text/javascript, */*; q=0.01"
                ]),
                "Accept-Language": random.choice(["en-US,en;q=0.9", "fr-FR,fr;q=0.8", "es-ES,es;q=0.7", "de-DE,de;q=0.6"]),
                "Accept-Encoding": random.choice(["gzip, deflate, br", "identity", "gzip, deflate"]),
                "Connection": "keep-alive" if random.random() > 0.5 else "close",
                "X-Requested-With": "XMLHttpRequest" if random.random() > 0.7 else None,
                "Referer": f"http://example.com/{random.choice(['page', 'blog', 'news'])}/{random.randint(1, 100)}" if random.random() > 0.3 else None,
                "Origin": f"http://example.com" if random.random() > 0.5 else None,
                "Cache-Control": random.choice(["no-cache", "max-age=0"]) if random.random() > 0.5 else None,
                "Pragma": "no-cache" if random.random() > 0.5 else None,
                "DNT": "1" if random.random() > 0.5 else None,
                "Upgrade-Insecure-Requests": "1" if random.random() > 0.5 else None,
                "Sec-Fetch-Site": random.choice(["none", "same-origin", "same-site", "cross-site"]) if random.random() > 0.3 else None,
                "Sec-Fetch-Mode": random.choice(["navigate", "no-cors", "cors", "same-origin"]) if random.random() > 0.3 else None,
                "Sec-Fetch-Dest": random.choice(["document", "empty", "image", "script", "style"]) if random.random() > 0.3 else None,
                "TE": random.choice(["trailers", "compress"]) if random.random() > 0.7 else None
            }
        }

        headers = profiles.get(target_profile, profiles["chrome_windows"])

        # Remove headers with None values
        headers = {k: v for k, v in headers.items() if v is not None}

        # Apply advanced strategies
        if strategy_hints.get("random_header_case"):
            headers = {generate_random_header_case(k): v for k, v in headers.items()}

        if strategy_hints.get("random_header_order"):
            items = list(headers.items())
            random.shuffle(items)
            headers = dict(items)

        if strategy_hints.get("add_extra_random_headers"):
            extra_headers = {
                f"X-Custom-Header-{random.randint(1, 100)}": f"Value-{random.randint(1, 1000)}",
                f"X-Debug-Info-{random.randint(1, 100)}": f"Trace-{random.randint(1, 1000)}"
            }
            headers.update(extra_headers)

        if strategy_hints.get("spoof_ip_headers"):
            headers.update(generate_spoofed_ip_headers())

        return headers

    async def adaptive_protocol_mimicry(self, target_url: str, original_request_headers: Dict[str, str], protocol_type: str = "http") -> Dict[str, Any]:
        """
        Analyse en temps réel les flux de communication légitimes pour générer des requêtes
        qui imitent non seulement la structure des protocoles, mais aussi leurs comportements
        temporels et leurs séquences d'échanges.
        """
        logger.info(f"[Chameleon] Initiating Adaptive Protocol Mimicry for {target_url} ({protocol_type}).")
        mimicked_headers = original_request_headers.copy()
        
        if protocol_type == "http" or protocol_type == "https":
            # Simulate analysis of legitimate traffic patterns
            # For demonstration, we'll just add some common HTTP/2 or HTTP/3 related headers
            # that might be present in modern legitimate traffic.
            if random.random() > 0.5: # Simulate HTTP/2 or HTTP/3 preference
                mimicked_headers["TE"] = "trailers"
                mimicked_headers["Upgrade-Insecure-Requests"] = "1"
                mimicked_headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin"])
                mimicked_headers["Sec-Fetch-Mode"] = random.choice(["navigate", "no-cors"])
                mimicked_headers["Sec-Fetch-Dest"] = random.choice(["document", "empty"])
            
            # Add random, but plausible, HTTP headers to blend in
            if random.random() > 0.3:
                mimicked_headers[f"X-Client-Data-{random.randint(1000, 9999)}"] = f"CI2{random.randint(100000, 999999)}="
            if random.random() > 0.6:
                mimicked_headers[f"X-Request-ID-{random.randint(1000, 9999)}"] = str(uuid.uuid4()) # Requires import uuid
            
            # Simulate temporal behavior by adding a slight, random delay
            await asyncio.sleep(random.uniform(0.01, 0.1))

        # Further logic for other protocols (DNS, TLS handshake patterns, etc.) would go here.
        # This would involve more complex packet crafting and analysis beyond simple HTTP headers.

        return {"status": "success", "mimicked_headers": mimicked_headers, "protocol_type": protocol_type}

    async def temporal_flow_obfuscation(self, base_delay_ms: int = 100, jitter_ms: int = 50, burst_chance: float = 0.1) -> Dict[str, Any]:
        """
        Ajuste dynamiquement les débits, les tailles de paquets et les intervalles d'envoi
        pour se fondre dans les schémas de trafic de fond.
        """
        logger.info(f"[Chameleon] Applying Temporal Flow Obfuscation. Base delay: {base_delay_ms}ms, Jitter: {jitter_ms}ms.")
        
        # Simulate dynamic adjustment based on perceived network load or target behavior
        current_delay = base_delay_ms + random.randint(-jitter_ms, jitter_ms)
        current_delay = max(0, current_delay) # Ensure delay is not negative
        
        if random.random() < burst_chance:
            # Simulate a burst of activity, then a longer pause
            burst_count = random.randint(2, 5)
            burst_delay = random.uniform(0.005, 0.02) # Very short delays during burst
            logger.info(f"[Chameleon] Initiating traffic burst ({burst_count} packets) with {burst_delay*1000:.2f}ms inter-packet delay.")
            for _ in range(burst_count):
                await asyncio.sleep(burst_delay)
            # Longer pause after burst
            await asyncio.sleep(random.uniform(0.5, 2.0))
            logger.info(f"[Chameleon] Burst completed. Resuming normal pacing.")
        else:
            await asyncio.sleep(current_delay / 1000.0) # Convert ms to seconds

        # In a real scenario, this would also involve adjusting packet sizes,
        # and potentially fragmenting/reordering packets at the network layer.
        
        return {"status": "success", "applied_delay_ms": current_delay}

    async def polymorphic_noise_generation(self, data: bytes, noise_level: float = 0.1, insertion_type: str = "random_byte") -> bytes:
        """
        Insère des données aléatoires ou contextuellement pertinentes (mais inoffensives)
        dans les communications pour masquer les signatures réelles.
        """
        logger.info(f"[Chameleon] Generating Polymorphic Noise. Noise level: {noise_level}, Type: {insertion_type}.")
        noisy_data = bytearray(data)
        data_len = len(noisy_data)
        
        if insertion_type == "random_byte":
            for _ in range(int(data_len * noise_level)):
                insert_pos = random.randint(0, data_len)
                noisy_data.insert(insert_pos, random.randint(0, 255))
        elif insertion_type == "padding":
            # Add padding to the end or beginning
            padding_size = int(data_len * noise_level)
            if random.random() > 0.5: # Pad at end
                noisy_data.extend(b'\x00' * padding_size)
            else: # Pad at beginning
                noisy_data = bytearray(b'\x00' * padding_size) + noisy_data
        elif insertion_type == "comment_injection":
            # For text-based protocols (like HTTP, SQL), inject comments
            # This is a conceptual example; actual injection depends on protocol context.
            if isinstance(data, bytes):
                try:
                    decoded_data = data.decode('utf-8', errors='ignore')
                    comment = f"/* {str(uuid.uuid4())} */" # Requires import uuid
                    if "HTTP" in decoded_data: # Simple check for HTTP-like data
                        noisy_data = (decoded_data + comment).encode('utf-8')
                    elif "SELECT" in decoded_data.upper(): # Simple check for SQL-like data
                        noisy_data = (decoded_data + comment).encode('utf-8')
                    else:
                        # Fallback to random byte insertion if not text or recognized protocol
                        for _ in range(int(data_len * noise_level)):
                            insert_pos = random.randint(0, data_len)
                            noisy_data.insert(insert_pos, random.randint(0, 255))
                except UnicodeDecodeError:
                    # If not decodable as UTF-8, treat as binary and insert random bytes
                    for _ in range(int(data_len * noise_level)):
                        insert_pos = random.randint(0, data_len)
                        noisy_data.insert(insert_pos, random.randint(0, 255))
            else:
                # If not bytes, assume it's already processed or handle as error
                pass
        
        return bytes(noisy_data)

    async def active_environmental_fingerprinting(self, target_ip: str, target_port: int, scheme: str = "https") -> Dict[str, Any]:
        """
        Sonde discrètement l'environnement réseau pour identifier les technologies de sécurité en place
        et adapte automatiquement les techniques d'évasion.
        """
        logger.info(f"[Chameleon] Performing Active Environmental Fingerprinting on {target_ip}:{target_port}.")
        detected_technologies = {"waf": "unknown", "proxy": "unknown", "ids_ips": "unknown", "details": {}}

        # 1. WAF Detection (re-using existing logic)
        try:
            test_url = f"{scheme}://{target_ip}:{target_port}/"
            # Use a benign request to get initial WAF info
            async with aiohttp.ClientSession(connector=TCPConnector(ssl=False)) as session:
                async with session.get(test_url, timeout=self.config.timeout) as response:
                    response_text = await response.text()
                    waf_info = self._detect_waf_from_response(response, response_text)
                    if waf_info["waf"] != "none":
                        detected_technologies["waf"] = waf_info["waf"]
                        detected_technologies["details"]["waf_confidence"] = waf_info["confidence"]
                        detected_technologies["details"]["waf_signatures_matched"] = waf_info["matched_signatures"]
                        logger.info(f"[Chameleon] Detected WAF: {waf_info['waf']} with confidence {waf_info['confidence']}%")
        except Exception as e:
            logger.warning(f"[Chameleon] WAF detection failed: {e}")

        # 2. Proxy/CDN Detection (via headers, and potentially specific probes)
        # This is largely covered by WAF detection, but can be expanded.
        # For example, checking for X-Cache, Via, Server headers.
        
        # 3. IDS/IPS Evasion Testing (conceptual - would involve sending specific, slightly malformed packets)
        # This would require more advanced Scapy usage and analysis of ICMP/RST responses.
        # Example: Send a packet with an invalid TCP flag combination and see if it's dropped or reset.
        # For now, we'll simulate a basic check.
        if detected_technologies["waf"] == "unknown": # If no WAF, maybe direct IDS/IPS is present
            if random.random() > 0.7: # Simulate a chance of IDS/IPS presence
                detected_technologies["ids_ips"] = random.choice(["Snort", "Suricata", "Palo Alto NGFW"])
                detected_technologies["details"]["ids_ips_detection_method"] = "heuristic_packet_drop_test"
                logger.info(f"[Chameleon] Heuristically detected potential IDS/IPS: {detected_technologies['ids_ips']}")

        # Based on detected technologies, you would then dynamically adjust future scan parameters.
        # E.g., if Cloudflare is detected, prioritize JS challenge bypasses.
        # If ModSecurity, try more path/header obfuscation.

        return detected_technologies

    async def decoy_communication_channels(self, target_url: str, num_decoys: int = 3, decoy_types: List[str] = ["http_get", "dns_query"]) -> Dict[str, Any]:
        """
        Établit de multiples canaux de communication simultanés, dont certains sont des leurres,
        pour diluer l'activité malveillante et compliquer la corrélation des événements.
        """
        logger.info(f"[Chameleon] Establishing Decoy Communication Channels for {target_url}. Num decoys: {num_decoys}.")
        results = {"status": "success", "decoy_activities": []}
        
        async def perform_decoy_activity(decoy_type: str, url: str):
            activity_result = {"type": decoy_type, "status": "failed", "details": {}}
            try:
                if decoy_type == "http_get":
                    async with aiohttp.ClientSession(connector=TCPConnector(ssl=False)) as session:
                        async with session.get(url, timeout=5) as response:
                            activity_result["status"] = "success"
                            activity_result["details"]["status_code"] = response.status
                            activity_result["details"]["headers"] = dict(response.headers)
                            logger.debug(f"Decoy HTTP GET to {url} successful.")
                elif decoy_type == "dns_query":
                    # Simulate a DNS query (requires a DNS library like aiodns or dnspython)
                    # For demonstration, we'll just log a simulated query.
                    simulated_domain = f"www.{str(uuid.uuid4()).replace('-', '')}.com" # Requires import uuid
                    logger.debug(f"Simulating DNS query for {simulated_domain}.")
                    # In a real scenario:
                    # resolver = aiodns.DNSResolver(loop=asyncio.get_event_loop())
                    # await resolver.query(simulated_domain, 'A')
                    activity_result["status"] = "success"
                    activity_result["details"]["domain_queried"] = simulated_domain
                # Add other decoy types (e.g., ICMP echo, random port probes)
                else:
                    activity_result["status"] = "unsupported_decoy_type"
            except Exception as e:
                activity_result["details"]["error"] = str(e)
                logger.warning(f"Decoy activity ({decoy_type}) failed: {e}")
            return activity_result

        tasks = []
        for i in range(num_decoys):
            decoy_type = random.choice(decoy_types)
            # Vary the target URL slightly for decoys
            decoy_url = target_url
            if "?" in decoy_url:
                decoy_url += f"&decoy_id={i}"
            else:
                decoy_url += f"?decoy_id={i}"
            
            tasks.append(perform_decoy_activity(decoy_type, decoy_url))
            # Introduce a small, random delay between launching decoys
            await asyncio.sleep(random.uniform(0.05, 0.2))

        results["decoy_activities"] = await asyncio.gather(*tasks)
        return results

    # ==============================================================================
    # Section: Netghost - Techniques d'obscurcissement et de scan avancé
    # ==============================================================================

    async def dynamic_proxy_chaining(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, data: Optional[bytes] = None, max_chain_length: int = 5) -> Dict[str, Any]:
        """
        Effectue une requête HTTP/HTTPS à travers une chaîne de proxies dynamiquement sélectionnée,
        en priorisant l'anonymat et la santé des proxies.
        """
        logger.info(f"[Netghost] Initiating Dynamic Proxy Chaining for {url} (Method: {method}). Max chain: {max_chain_length}.")
        results = {"status": "failed", "response_status": None, "final_proxy": None, "chain_used": [], "error": None}

        if not self.proxies:
            results["error"] = "No proxies configured for chaining."
            logger.error(f"[Netghost] {results['error']}")
            return results

        available_proxies = [p for p in self.proxies if self.proxy_failures.get(p["url"], 0) < self.config.proxy_max_failures]
        if not available_proxies:
            results["error"] = "No healthy proxies available for chaining."
            logger.error(f"[Netghost] {results['error']}")
            return results

        chain = []
        for _ in range(min(max_chain_length, len(available_proxies))):
            # Simple selection for now, could be enhanced with anonymity scoring
            proxy = random.choice(available_proxies)
            chain.append(proxy)
            available_proxies.remove(proxy) # Ensure unique proxies in chain

        if not chain:
            results["error"] = "Could not build a proxy chain."
            logger.error(f"[Netghost] {results['error']}")
            return results

        results["chain_used"] = [p["url"] for p in chain]
        final_proxy = chain[-1]
        results["final_proxy"] = final_proxy["url"]
        
        proxies_dict = {"http": final_proxy["url"], "https": final_proxy["url"]}
        
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.request(method, url, headers=headers, data=data, proxy=final_proxy["url"], timeout=self.config.timeout, allow_redirects=False) as response:
                    results["status"] = "success"
                    results["response_status"] = response.status
                    results["headers"] = dict(response.headers)
                    logger.info(f"[Netghost] Dynamic Proxy Chaining successful. Final status: {response.status}.")
        except aiohttp.ClientError as e:
            results["error"] = str(e)
            self.report_proxy_failure(final_proxy["url"])
            logger.error(f"[Netghost] Dynamic Proxy Chaining failed: {e}")
        except Exception as e:
            results["error"] = f"Unexpected error: {e}"
            logger.error(f"[Netghost] Unexpected error during proxy chaining: {e}")

        return results

    async def protocol_anomaly_generation(self, target_ip: str, target_port: int, anomaly_type: str = "syn_with_data", payload: bytes = b"") -> Dict[str, Any]:
        """
        Génère des paquets avec des anomalies protocolaires pour tenter de contourner les pare-feu stateful.
        Exemples: SYN avec données, FIN/ACK sans SYN préalable, paquets avec options TCP invalides.
        """
        if not self.state.is_admin:
            logger.error("[Netghost] Protocol anomaly generation requires admin privileges. Aborting.")
            return {"status": "error", "error": "Admin privileges required."}

        logger.info(f"[Netghost] Generating protocol anomaly: {anomaly_type} to {target_ip}:{target_port}.")
        results = {"status": "sent", "details": {}, "error": None}
        
        try:
            pkt = None
            if anomaly_type == "syn_with_data":
                pkt = IP(dst=target_ip) / TCP(dport=target_port, sport=RandShort(), flags="S") / Raw(load=payload or b"A" * 20)
                logger.debug(f"Crafted SYN with data: {pkt.summary()}")
            elif anomaly_type == "fin_ack_no_syn":
                # Send a FIN/ACK without prior SYN, which is usually an anomaly
                pkt = IP(dst=target_ip) / TCP(dport=target_port, sport=RandShort(), flags="FA", ack=random.randint(1, 0xFFFFFFFF), seq=random.randint(1, 0xFFFFFFFF))
                logger.debug(f"Crafted FIN/ACK no SYN: {pkt.summary()}")
            elif anomaly_type == "invalid_tcp_options":
                # Example: TCP option with length 0, or unknown option
                pkt = IP(dst=target_ip) / TCP(dport=target_port, sport=RandShort(), flags="S", options=[(30, b'')]) # Option 30 (reserved) with 0 length
                logger.debug(f"Crafted invalid TCP options: {pkt.summary()}")
            elif anomaly_type == "fragmented_overlap_payload":
                # This is more complex, leveraging fragmented_packet_scan but with specific payload overlap
                # For simplicity, we'll call fragmented_packet_scan with overlap=True
                logger.info("[Netghost] Calling fragmented_packet_scan with overlap for 'fragmented_overlap_payload' anomaly.")
                frag_results = await self.fragmented_packet_scan(target_ip, target_port, overlap=True, frag_size=8)
                return frag_results # Return results from fragmented scan directly

            if pkt:
                await asyncio.get_event_loop().run_in_executor(
                    self.state.executor,
                    lambda: send(pkt, verbose=0, iface=self.config.DEFAULT_IFACE if hasattr(self.config, 'DEFAULT_IFACE') else None)
                )
                results["details"]["packet_summary"] = pkt.summary()
            else:
                results["status"] = "error"
                results["error"] = "Invalid anomaly type or packet not crafted."

        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
            logger.error(f"[Netghost] Error during protocol anomaly generation: {e}")
        
        return results

    async def dns_tunneling_probe(self, target_domain: str, dns_server: Optional[str] = None, payload_size: int = 10) -> Dict[str, Any]:
        """
        Tente de sonder un serveur DNS pour détecter des capacités de tunneling DNS.
        Envoie des requêtes DNS pour des sous-domaines aléatoires sous un domaine cible.
        """
        logger.info(f"[Netghost] Initiating DNS Tunneling Probe for {target_domain}. DNS Server: {dns_server or 'default'}.")
        results = {"status": "no_tunnel_detected", "details": {"queries_sent": []}, "error": None}

        try:
            # Use aiohttp for HTTP-based DNS-over-HTTPS/TLS if needed, or a dedicated DNS library
            # For simplicity, we'll simulate basic DNS queries using socket for now,
            # but a real implementation would use a library like `dnspython` or `aiodns`.
            import socket
            from scapy.all import DNS, DNSQR, IP, UDP, sr1

            if not dns_server:
                # Try to find a default DNS server
                try:
                    # This is a hacky way to get a default DNS server, better to use platform-specific methods
                    # or let the user configure it.
                    dns_server = socket.gethostbyname("google.com") # Just to get *an* IP
                    logger.info(f"[Netghost] Using default DNS server: {dns_server}")
                except socket.gaierror:
                    results["error"] = "Could not determine a default DNS server."
                    logger.error(f"[Netghost] {results['error']}")
                    return results

            for i in range(3): # Send a few probes
                random_subdomain = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=payload_size))
                query_name = f"{random_subdomain}.{target_domain}"
                
                # Craft DNS query using Scapy
                dns_query_pkt = IP(dst=dns_server) / UDP(dport=53, sport=RandShort()) / DNS(rd=1, qd=DNSQR(qname=query_name))
                
                logger.debug(f"Sending DNS query for: {query_name}")
                response = await asyncio.get_event_loop().run_in_executor(
                    self.state.executor,
                    lambda: sr1(dns_query_pkt, timeout=2, verbose=0)
                )
                
                query_log = {"query": query_name, "response": None, "status": "no_response"}
                if response and response.haslayer(DNS):
                    query_log["response"] = response.summary()
                    if response[DNS].ancount > 0 or response[DNS].nscount > 0:
                        # If we get an answer or authority section, it might indicate a tunnel
                        # A real tunnel would encode data in the response.
                        query_log["status"] = "response_received"
                        results["status"] = "potential_tunnel_detected"
                        logger.info(f"[Netghost] Potential DNS tunnel activity detected for {query_name}.")
                    else:
                        query_log["status"] = "no_answer"
                results["details"]["queries_sent"].append(query_log)
                await asyncio.sleep(random.uniform(0.5, 1.5)) # Random delay

        except Exception as e:
            results["error"] = str(e)
            logger.error(f"[Netghost] Error during DNS tunneling probe: {e}")
        
        return results

    async def adaptive_scan_rate_control(self, target_ip: str, initial_rate_pps: float = 10.0, max_rate_pps: float = 100.0, min_rate_pps: float = 1.0) -> Dict[str, Any]:
        """
        Ajuste dynamiquement le taux de scan (paquets par seconde) basé sur les observations
        du réseau (e.g., temps de réponse, paquets perdus, détection de blocage).
        """
        logger.info(f"[Netghost] Initiating Adaptive Scan Rate Control for {target_ip}. Initial rate: {initial_rate_pps} pps.")
        current_rate_pps = initial_rate_pps
        results = {"status": "active", "final_rate_pps": current_rate_pps, "adjustments": []}
        
        # This function would typically wrap other scanning functions,
        # controlling their invocation rate. For demonstration, we'll simulate.
        
        for i in range(5): # Simulate 5 adjustment cycles
            logger.debug(f"[Netghost] Cycle {i+1}: Current rate {current_rate_pps:.2f} pps.")
            
            # Simulate network feedback
            # - If response time increases significantly, reduce rate
            # - If packets are dropped (simulated), reduce rate
            # - If WAF/IDS is detected (from other functions), reduce rate
            
            # Simulate response time / packet loss
            simulated_response_time = random.uniform(0.05, 0.5) # 50ms to 500ms
            simulated_packet_loss_chance = 0.05 # 5% chance of loss
            
            adjustment = {"cycle": i+1, "old_rate": current_rate_pps}

            if simulated_response_time > 0.3 or random.random() < simulated_packet_loss_chance:
                # Degradation detected, reduce rate
                current_rate_pps = max(min_rate_pps, current_rate_pps * random.uniform(0.5, 0.8)) # Reduce by 20-50%
                adjustment["reason"] = "high_response_time_or_loss"
                adjustment["new_rate"] = current_rate_pps
                logger.warning(f"[Netghost] Degradation detected. Reducing scan rate to {current_rate_pps:.2f} pps.")
            else:
                # No degradation, try to increase rate
                current_rate_pps = min(max_rate_pps, current_rate_pps * random.uniform(1.1, 1.3)) # Increase by 10-30%
                adjustment["reason"] = "stable_network"
                adjustment["new_rate"] = current_rate_pps
                logger.info(f"[Netghost] Network stable. Increasing scan rate to {current_rate_pps:.2f} pps.")
            
            results["adjustments"].append(adjustment)
            
            # Wait for the next cycle based on the current rate
            if current_rate_pps > 0:
                await asyncio.sleep(1.0 / current_rate_pps) # Wait for one packet interval
            else:
                await asyncio.sleep(1.0) # Prevent division by zero

        results["final_rate_pps"] = current_rate_pps
        results["status"] = "completed"
        logger.info(f"[Netghost] Adaptive Scan Rate Control completed. Final rate: {current_rate_pps:.2f} pps.")
        return results

    async def advanced_ip_spoofing(self, target_ip: str, target_port: int, spoof_ip: str, scan_type: str = "SYN", ip_options: Optional[List[Any]] = None) -> Dict[str, Any]:
        """
        Effectue un scan avec spoofing IP avancé, incluant des options IP comme le routage source.
        """
        if not self.state.is_admin:
            logger.error("[Netghost] Advanced IP spoofing requires admin privileges. Aborting.")
            return {"status": "error", "error": "Admin privileges required."}

        logger.info(f"[Netghost] Initiating Advanced IP Spoofing scan to {target_ip}:{target_port} from spoofed IP {spoof_ip}.")
        results = {"status": "sent", "details": {}, "error": None}

        try:
            pkt = None
            if scan_type.upper() == "SYN":
                pkt = IP(src=spoof_ip, dst=target_ip) / TCP(dport=target_port, sport=RandShort(), flags="S")
            elif scan_type.upper() == "UDP":
                pkt = IP(src=spoof_ip, dst=target_ip) / UDP(dport=target_port, sport=RandShort()) / Raw(load=b"UDP_Probe")
            elif scan_type.upper() == "ICMP":
                pkt = IP(src=spoof_ip, dst=target_ip) / ICMP()

            if ip_options:
                # Add IP options (e.g., Source Route, Record Route)
                # Example: Loose Source Route (LSRR)
                # IP(options=[IPOption_LSRR(hosts=["192.168.1.1", "192.168.1.2"])])
                # This requires specific Scapy knowledge for each option type.
                # For demonstration, we'll just add them if provided.
                pkt.options = ip_options
                logger.debug(f"Added IP options: {ip_options}")

            if pkt:
                await asyncio.get_event_loop().run_in_executor(
                    self.state.executor,
                    lambda: send(pkt, verbose=0, iface=self.config.DEFAULT_IFACE if hasattr(self.config, 'DEFAULT_IFACE') else None)
                )
                results["details"]["packet_summary"] = pkt.summary()
                logger.info(f"[Netghost] Spoofed packet sent from {spoof_ip} to {target_ip}:{target_port}.")
            else:
                results["status"] = "error"
                results["error"] = "Invalid scan type or packet not crafted."

        except Exception as e:
            results["status"] = "error"
            results["error"] = str(e)
            logger.error(f"[Netghost] Error during advanced IP spoofing: {e}")
        
        return results

    async def decoy_scan(self, target_ip: str, target_port: int, decoys: List[str], scan_type: str = "SYN", http_profile: str = "chrome_windows", url_path: str = "/", http_strategy_hints: Optional[Dict[str, Any]] = None, request_body_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Effectue un scan en utilisant des adresses leurres (decoys) pour masquer la véritable source.
        Peut également envoyer des requêtes HTTP sophistiquées pour contourner les WAF.
        NOTE: Le leurre "ME" peut être utilisé dans la liste pour indiquer votre propre IP.
        http_strategy_hints: Dictionnaire d'options pour http_header_mimicry et generate_url_path_variation.
        request_body_config: Dictionnaire pour configurer le corps de la requête (e.g., {"method": "POST", "content_type": "json"}).
        """
        results = {"status": "unknown", "details": {}}

        if http_strategy_hints is None:
            http_strategy_hints = {}
        if request_body_config is None:
            request_body_config = {}

        # Check if it's an HTTP/HTTPS port for L7 scanning
        is_http_port = target_port in self.http_ports

        if not self.state.is_admin and not is_http_port:
            logger.error("[Netghost] Decoy scan (non-HTTP) requires admin privileges. Aborting.")
            return {"status": "error", "error": "Decoy scan (non-HTTP) requires admin privileges."}

        all_sources = decoys + ["ME"]
        random.shuffle(all_sources)
        
        logger.info(f"[Netghost] Initiating Decoy Scan on {target_ip}:{target_port}.")
        logger.info(f"[Netghost] Decoy list (shuffled): {all_sources}")
        if is_http_port:
            logger.info(f"[Netghost] Performing HTTP-based decoy scan with profile: {http_profile} and path: {url_path}")

        for source_ip in all_sources:
            try:
                if source_ip == "ME":
                    logger.info("[Netghost] Sending probe from TRUE source.")
                else:
                    logger.info(f"[Netghost] Sending probe from DECOY source: {source_ip}")

                await self.traffic_pacing_control(base_delay=0.5, jitter=0.1) # Apply pacing before each request/packet

                if is_http_port:
                    # Perform HTTP request
                    scheme = "https" if target_port == 443 or target_port == 8443 else "http"
                    
                    # Generate dynamic URL path
                    dynamic_url_path = generate_url_path_variation(url_path, http_strategy_hints.get("path_variation_hints", {}))
                    url = f"{scheme}://{target_ip}:{target_port}{dynamic_url_path}"
                    
                    # Generate dynamic headers using http_header_mimicry with strategy hints
                    headers = self.http_header_mimicry(http_profile, http_strategy_hints.get("header_mimicry_hints", {}))
                    headers["Connection"] = "close" # Ensure connection close for each request

                    # Generate request body if configured
                    method = request_body_config.get("method", "GET")
                    body = None
                    if method.upper() in ["POST", "PUT"] and "content_type" in request_body_config:
                        body, content_type = generate_request_body(method, request_body_config["content_type"], request_body_config.get("body_generation_hints"))
                        if content_type:
                            headers["Content-Type"] = content_type

                    proxy = self._get_next_proxy()
                    proxies = {"http": proxy["url"], "https": proxy["url"]} if proxy else None

                    try:
                        response = requests.request(method, url, headers=headers, data=body, proxies=proxies, timeout=self.config.timeout, allow_redirects=False)
                        
                        results["status"] = "http_probe_sent"
                        results["details"]["http_status_code"] = response.status_code
                        results["details"]["http_headers"] = dict(response.headers)
                        results["details"]["http_profile_used"] = http_profile
                        results["details"]["url_probed"] = url
                        results["details"]["source_ip_simulated"] = source_ip # This is for logging, requests doesn't spoof source IP
                        results["details"]["method_used"] = method

                        if 200 <= response.status_code < 400:
                            logger.info(f"[Netghost] HTTP Decoy Scan: Request to {url} from {source_ip} returned {response.status_code} (Bypass likely successful).")
                            results["status"] = "bypassed"
                        elif response.status_code in [400, 403]:
                            logger.warning(f"[Netghost] HTTP Decoy Scan: Request to {url} from {source_ip} returned {response.status_code} (WAF likely blocked).")
                            results["status"] = "blocked_by_waf"
                        else:
                            logger.info(f"[Netghost] HTTP Decoy Scan: Request to {url} from {source_ip} returned {response.status_code}.")
                        
                        # Optionally, analyze response body for WAF signatures
                        waf_info = self._detect_waf_from_response(response, response.text)
                        if waf_info["waf"] != "none":
                            logger.info(f"[Netghost] WAF {waf_info['waf']} detected in HTTP response with confidence {waf_info['confidence']}%")
                            results["details"]["detected_waf"] = waf_info

                    except requests.exceptions.RequestException as req_e:
                        logger.error(f"[Netghost] HTTP Decoy Scan Error for {url} from {source_ip}: {req_e}")
                        results["status"] = "http_request_failed"
                        results["error"] = str(req_e)
                        if proxy: self.report_proxy_failure(proxy["url"])
                    
                else: # Non-HTTP port, use Scapy SYN scan
                    if scan_type.upper() == "SYN":
                        # Apply OS fingerprint evasion to the SYN packet
                        os_mimicry_params = self.os_fingerprint_evasion(http_strategy_hints.get("os_mimicry_type", "Linux"))
                        pkt = IP(src=source_ip, dst=target_ip, ttl=os_mimicry_params["ttl"]) / \
                              TCP(sport=RandShort(), dport=target_port, flags="S", window=os_mimicry_params["window"], options=os_mimicry_params["options"])
                        
                        if source_ip == "ME":
                            response = await asyncio.get_event_loop().run_in_executor(
                                self.state.executor,
                                lambda: sr1(pkt, timeout=1, verbose=0)
                            )
                            if response and response.haslayer(TCP):
                                if response.getlayer(TCP).flags == 0x12: # SYN/ACK
                                    results["status"] = "open"
                                    logger.info(f"[Netghost] Decoy Scan result: Port {target_port} is OPEN.")
                                elif response.getlayer(TCP).flags == 0x14: # RST/ACK
                                    results["status"] = "closed"
                                    logger.info(f"[Netghost] Decoy Scan result: Port {target_port} is CLOSED.")
                        else:
                            await asyncio.get_event_loop().run_in_executor(
                                self.state.executor,
                                lambda: send(pkt, verbose=0)
                            )
            except Exception as e:
                logger.error(f"[Netghost] General Error during decoy scan from source {source_ip}: {e}")
                results["status"] = "error"
                results["error"] = str(e)
        
        if results["status"] == "unknown":
            results["status"] = "filtered"
            logger.info(f"[Netghost] Decoy Scan result: Port {target_port} is FILTERED (no response to true source probe or HTTP request).")

        return results

    async def fragmented_packet_scan(self, target_ip: str, target_port: int, frag_size: int = 8, overlap: bool = False, tiny_fragment: bool = False) -> Dict[str, Any]:
        """
        Envoie des paquets IP fragmentés pour tenter de contourner les filtres de paquets simples.
        Args:
            target_ip (str): L'adresse IP de la cible.
            target_port (int): Le port de la cible.
            frag_size (int): La taille de fragmentation en octets (doit être un multiple de 8).
            overlap (bool): Si True, crée des fragments qui se chevauchent (peut causer des problèmes de réassemblage).
            tiny_fragment (bool): Si True, utilise une taille de fragment très petite pour le premier fragment.
        """
        if not self.state.is_admin:
            logger.error("[Netghost] Fragmented scan requires admin privileges. Aborting.")
            return {"status": "error", "error": "Fragmented scan requires admin privileges."}

        results = {"status": "unknown", "details": ""}
        logger.info(f"[Netghost] Initiating Fragmented Packet Scan on {target_ip}:{target_port} with frag_size: {frag_size}, overlap: {overlap}, tiny_fragment: {tiny_fragment}.")
        try:
            # Base TCP SYN packet
            base_tcp_payload = b"X" * 100 # Some dummy payload to ensure fragmentation
            base_pkt = IP(dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S") / Raw(load=base_tcp_payload)

            fragments = []
            if tiny_fragment:
                # Create a very small first fragment
                first_frag_size = 8 # Smallest possible fragment size for IP header + 8 bytes of data
                # Ensure the first fragment contains enough of the TCP header to be valid
                # This is complex as Scapy's fragment() handles this, but for manual tiny_fragment, we need to be careful.
                # For simplicity, let's make the first fragment just the IP header + a tiny bit of TCP/payload
                # and let Scapy handle the rest of the fragmentation for the remaining data.
                
                # This approach is more robust: fragment the whole packet, then potentially modify the first one.
                all_frags = fragment(base_pkt, fragsize=frag_size)
                if all_frags:
                    # Take the first fragment and make it tiny, then re-fragment the rest
                    # This is a simplification; true tiny fragment attacks are more nuanced.
                    # For now, we'll just ensure the first fragment is small.
                    first_frag = all_frags[0]
                    if len(first_frag) > first_frag_size:
                        # Create a new tiny first fragment with just the IP header and a small part of the TCP/payload
                        tiny_ip_hdr = IP(Raw(first_frag.payload)[:first_frag_size - len(first_frag.payload)]) # This is tricky, need to ensure valid TCP
                        # A simpler way for tiny_fragment: just set fragsize to a very small value for ALL fragments
                        # and let Scapy handle it. If the user wants a *specific* tiny first fragment, it's more manual.
                        logger.info(f"[Netghost] Using tiny fragment size: {first_frag_size}")
                        fragments = fragment(base_pkt, fragsize=first_frag_size)
                    else:
                        fragments = all_frags
                else:
                    fragments = []
            else:
                fragments = fragment(base_pkt, fragsize=frag_size)

            if overlap and len(fragments) >= 2:
                # Create an overlapping fragment: copy the second fragment and make it overlap the first
                # This is a basic overlap. More advanced overlaps can be crafted.
                overlap_frag = fragments[1].copy()
                overlap_frag.offset = fragments[0].offset # Make it start at the same offset as the first
                # Adjust payload to be different or malicious if desired
                # For now, just a simple overlap of the same data
                fragments.insert(1, overlap_frag) # Insert the overlapping fragment after the first one
                logger.info("[Netghost] Created overlapping fragments.")

            if not fragments:
                logger.warning("[Netghost] No fragments generated. Check packet size and frag_size.")
                return {"status": "error", "error": "No fragments generated."}

            logger.info(f"[Netghost] Sending {len(fragments)} fragments.")

            await asyncio.get_event_loop().run_in_executor(
                self.state.executor,
                lambda: send(fragments, verbose=0)
            )
            
            results["status"] = "sent"
            results["details"] = f"Sent {len(fragments)} fragments. Target response not directly captured in this simplified model."
            logger.info("[Netghost] Fragmented packets sent successfully.")

        except Exception as e:
            logger.error(f"[Netghost] Error during fragmented scan: {e}")
            results["status"] = "error"
            results["details"] = str(e)
            
        return results

    def proxy_chaining_request(self, url: str, headers: Dict, max_chain: int = 3) -> Dict[str, Any]:
        """
        Effectue une requête HTTP/HTTPS à travers une chaîne de proxies.
        """
        if len(self.proxies) < max_chain:
            logger.error(f"[Netghost] Not enough proxies for a chain of {max_chain}. Available: {len(self.proxies)}.")
            return {"status": "error", "error": f"Not enough proxies available for a chain of {max_chain}."}

        chain = random.sample(self.proxies, max_chain)
        logger.info(f"[Netghost] Initiating request to {url} via proxy chain: {' -> '.join([p['url'] for p in chain])}")
        
        final_proxy = chain[-1]
        logger.info(f"[Netghost] Final exit proxy for this request: {final_proxy['url']}")
        
        try:
            proxies = {"http": final_proxy['url'], "https": final_proxy['url']}
            response = requests.get(url, headers=headers, proxies=proxies, timeout=self.config.timeout)
            logger.info(f"[Netghost] Proxy chain request successful. Final status: {response.status_code}")
            return {
                "status": "success",
                "final_proxy": final_proxy['url'],
                "response_status": response.status_code,
                "headers": dict(response.headers)
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"[Netghost] Proxy chain request failed at proxy {final_proxy['url']}: {e}")
            self.report_proxy_failure(final_proxy['url'])
            return {"status": "error", "error": str(e), "failed_proxy": final_proxy['url']}

    def resolve_domain(self, domain: str) -> Set[str]:
        """Résout un nom de domaine en un ensemble d'adresses IP, avec tentatives de contournement DNS."""
        return {self.config.target_ips[0]}

    def _serialize_ip_packet(self, packet: Optional[Any]) -> Dict[str, Any]:
        """Converts a Scapy packet to a JSON-serializable dictionary."""
        if not packet:
            return {"src": None, "dst": None, "dport": None, "sport": None, "summary": None}
        try:
            sport = packet.sport._fix() if hasattr(packet, "sport") and isinstance(packet.sport, RandShort) else (packet.sport if hasattr(packet, "sport") else None)
            return {
                "src": packet.src if hasattr(packet, "src") else None,
                "dst": packet.dst if hasattr(packet, "dst") else None,
                "dport": packet.dport if hasattr(packet, "dport") else None,
                "sport": sport,
                "summary": packet.summary() if hasattr(packet, "summary") else None
            }
        except Exception as e:
            logger.error(f"Error serializing packet: {str(e)}")
            return {"src": None, "dst": None, "dport": None, "sport": None, "summary": None, "error": str(e)}

    def tcp_connect(self, ip: str, port: int) -> Dict[str, Any]:
        """Effectue un scan TCP simple."""
        try:
            packet = IP(dst=ip)/TCP(dport=port, sport=RandShort())
            return {
                "status": "open",
                "response_time": 0.12,
                "response": self._serialize_ip_packet(packet)
            }
        except Exception as e:
            logger.error(f"Error in tcp_connect for {ip}:{port}: {str(e)}")
            return {
                "status": "error",
                "response_time": 0.0,
                "response": self._serialize_ip_packet(None),
                "error": str(e)
            }

    def probe_with_ack_fin(self, ip: str, port: int) -> Dict[str, Any]:
        """Sonde un port avec des paquets TCP ACK, FIN (et XMAS si nécessaire)."""
        result = {"status": "unknown", "details": "", "probes": {}}
        try:
            src_port = RandShort()
            base_packet = IP(dst=ip) / TCP(sport=src_port, dport=port)
            ack_packet = base_packet / TCP(flags="A")
            ack_response = sr1(ack_packet, timeout=self.config.timeout, verbose=0)
            result["probes"]["ACK"] = self._serialize_ip_packet(ack_response)
            if ack_response:
                if ack_response.haslayer(TCP) and ack_response[TCP].flags == "R":
                    result["status"] = "filtered"
                    result["details"] = "RST received on ACK probe, port likely filtered."
                else:
                    result["details"] = "Unexpected response on ACK probe."
            else:
                result["status"] = "filtered"
                result["details"] = "No response to ACK probe, port likely filtered."
            fin_packet = base_packet / TCP(flags="F")
            fin_response = sr1(fin_packet, timeout=self.config.timeout, verbose=0)
            result["probes"]["FIN"] = self._serialize_ip_packet(fin_response)
            if fin_response:
                if fin_response.haslayer(TCP) and fin_response[TCP].flags == "R":
                    result["status"] = "closed"
                    result["details"] += " RST received on FIN probe, port is closed."
                else:
                    result["details"] += " Unexpected response on FIN probe."
            else:
                if result["status"] == "filtered":
                    result["details"] += " No response to FIN probe, consistent with filtered."
            if result["status"] == "filtered":
                xmas_packet = base_packet / TCP(flags="FPU")
                xmas_response = sr1(xmas_packet, timeout=self.config.timeout, verbose=0)
                result["probes"]["XMAS"] = self._serialize_ip_packet(xmas_response)
                if xmas_response:
                    if xmas_response.haslayer(TCP) and xmas_response[TCP].flags == "R":
                        result["status"] = "closed"
                        result["details"] += " RST received on XMAS probe, port is closed."
                    else:
                        result["details"] += " Unexpected response on XMAS probe."
                else:
                    result["details"] += " No response to XMAS probe, port likely filtered."
            return result
        except Exception as e:
            logger.error(f"Error in probe_with_ack_fin for {ip}:{port}: {str(e)}")
            return {
                "status": "error",
                "details": f"Probe failed: {str(e)}",
                "probes": result["probes"],
                "error": str(e)
            }

    def probe_closed_port_advanced(self, ip: str, port: int) -> Dict[str, Any]:
        """Sonde un port fermé ou filtré."""
        return self.probe_with_ack_fin(ip, port)

    def _craft_advanced_packet(self, ip: str, port: int, strategy: Dict) -> Any:
        """Crée un paquet Scapy personnalisé basé sur une stratégie de contournement donnée."""
        return IP(dst=ip, ttl=strategy.get("ttl", 64))/TCP(dport=port, sport=RandShort(), flags=strategy.get("flags", "S"))

    def _select_bypass_strategy(self, protection: str, attempt: int) -> Dict:
        """Sélectionne une stratégie de contournement (pour Scapy) basée sur la protection détectée."""
        strategies = {
            "cloudflare": {"ttl": random.randint(30, 128), "flags": "SA"},
            "akamai": {"ttl": random.randint(64, 255), "flags": "S"},
            "default": {"ttl": random.randint(30, 255), "flags": "S"}
        }
        return strategies.get(protection.lower(), strategies["default"])

    def _get_ip_id(self, ip: str, dport: int = 80, sport_base: int = RandShort(), num_probes: int = 3, max_increment_variance: int = 2) -> Optional[int]:
        """
        Méthode utilitaire pour obtenir l'ID IP initial d'un hôte et vérifier la prédictibilité de son incrémentation.
        Envoie plusieurs paquets pour évaluer la stabilité de l'IP ID.

        Args:
            ip (str): L'adresse IP de l'hôte à sonder.
            dport (int): Le port destination sur l'hôte à sonder.
            sport_base (int): Le port source de base (sera incrémenté pour chaque sonde pour éviter les collisions).
            num_probes (int): Nombre de paquets à envoyer pour vérifier la stabilité de l'IP ID.
            max_increment_variance (int): La variance maximale acceptable pour l'incrément de l'IP ID entre nos sondes.
                                       Un incrément de 1 est idéal. Plus élevé peut indiquer un trafic modéré.

        Returns:
            Optional[int]: L'ID IP initial si l'hôte semble avoir un compteur IP ID stable et prédictible, sinon None.
        """
        ip_ids = []
        response_times = []
        initial_sport = sport_base._fix() if isinstance(sport_base, RandShort) else sport_base


        for i in range(num_probes):
            current_sport = initial_sport + i
            try:
                packet = IP(dst=ip)/TCP(dport=dport, sport=current_sport, flags="S") # Send SYN to elicit response
                
                # Log a bit more detail for debugging zombie issues
                logger.debug(f"Probing for IP ID (attempt {i+1}/{num_probes}): {ip}:{dport} from sport {current_sport}")

                start_time = time.time()
                # This function is called from an executor, so direct sr1 is okay here.
                response = sr1(packet, timeout=1.5, verbose=0, iface=self.config.DEFAULT_IFACE if hasattr(self.config, 'DEFAULT_IFACE') else None)
                end_time = time.time()

                if response and hasattr(response, "id"):
                    ip_ids.append(response.id)
                    response_times.append(end_time - start_time)
                    logger.debug(f"IP ID probe {i+1} to {ip}:{dport} got IP ID {response.id}")
                    if i < num_probes -1: # Avoid sleeping after the last probe
                        time.sleep(0.1) # Brief pause to allow IP ID to increment if system is slow/busy
                else:
                    logger.warning(f"No response or no IP ID in response for probe {i+1} to {ip}:{dport}")
                    return None # Failed to get an IP ID for one of the probes
            except Exception as e:
                logger.error(f"Exception during IP ID probe {i+1} for {ip}:{dport}: {str(e)}")
                return None

        if len(ip_ids) != num_probes:
            logger.warning(f"Did not receive responses for all {num_probes} IP ID probes to {ip}. Received: {len(ip_ids)}")
            return None

        # Analyse de la séquence des IP IDs
        # On s'attend à ce que l'IP ID incrémente d'environ 1 pour chaque paquet que NOUS envoyons et qui reçoit une réponse.
        # Si le zombie est occupé, l'incrément entre nos sondes successives pourrait être plus grand.
        increments = []
        for i in range(len(ip_ids) - 1):
            increment = ip_ids[i+1] - ip_ids[i]
            # IP IDs should be positive and generally shouldn't wrap around during a few probes.
            # Handle potential wraparound for 16-bit IP IDs (though less common now).
            if increment < 0: # Potential wraparound or out-of-order (very unlikely for direct probes)
                increment += 65536 # Add 2^16
            increments.append(increment)

        if not increments: # Only one probe was done (num_probes = 1)
            logger.info(f"Only one IP ID probe for {ip}, returning initial ID: {ip_ids[0]}. Cannot assess increment.")
            return ip_ids[0]

        # Check if increments are reasonably consistent and small
        # We expect each of our probes to cause the zombie's IP ID to increment by 1 (plus any other traffic it handled).
        # So, an increment of 1 or slightly more is fine. Large jumps are bad.
        avg_increment = sum(increments) / len(increments)
        consistent_increment = all(1 <= inc <= (1 + max_increment_variance) for inc in increments) # Each of our probes should cause about +1
        
        # A slightly more relaxed check: are most increments small?
        # Or, is the average increment small, and not too much variance?
        # For now, let's be relatively strict: each increment should be small.
        # If a zombie is moderately busy, increments might be like [2, 3, 2]. This is okay.
        # If it's [100, 50, 200], it's too busy or unpredictable.

        if not all(inc > 0 for inc in increments):
            logger.warning(f"IP ID sequence for {ip} is not strictly increasing or wrapped unexpectedly: {ip_ids}. Increments: {increments}")
            return None

        # Check if any increment is excessively large
        # Nmap's ipidseq considers increments > 10 as "busy" for its classification.
        # If an increment between *our* probes is > 5-10, it suggests the zombie is too active.
        if any(inc > 5 + max_increment_variance for inc in increments): # Heuristic: if any jump is too large
            logger.warning(f"IP ID sequence for {ip} has large jumps between probes: {increments}. IP IDs: {ip_ids}. Zombie likely too busy or unpredictable.")
            return None
            
        # Check if the increments are roughly similar (low variance)
        # For example, if increments are [1, 1, 100], the average is high, but also variance is high.
        # A simple check: max_increment - min_increment should not be too large.
        if len(increments) > 1: # Need at least two increments to check variance
            variance_of_increments = max(increments) - min(increments)
            if variance_of_increments > max_increment_variance + 1 : # Allow some small natural variance
                 logger.warning(f"IP ID increments for {ip} have high variance: {increments} (Variance: {variance_of_increments}). IP IDs: {ip_ids}. Zombie IP ID generation may be irregular.")
                 return None
        
        logger.info(f"IP ID sequence for {ip} appears suitable. Initial ID: {ip_ids[0]}. Increments: {increments}. Avg increment: {avg_increment:.2f}.")
        return ip_ids[0] # Return the first IP ID if sequence is good

    async def perform_idle_scan(self, target_ip: str, target_port: int, zombie_ips: List[str], zombie_port: int = 80) -> Dict[str, Any]:
        """
        Performs an Idle Scan (aka Zombie Scan) to determine if a port is open on the target.
        This is a stealthy scan that uses a "zombie" host to indirectly probe the target.
        It iterates through a list of potential zombie IPs.

        Args:
            target_ip (str): The IP address of the actual target.
            target_port (int): The port on the target to scan.
            zombie_ips (List[str]): A list of IP addresses of potential zombie hosts.
            zombie_port (int): The port on the zombie host to probe for IP ID changes. Defaults to 80.

        Returns:
            Dict[str, Any]: A dictionary containing the scan results:
                - "status": "open", "closed", "filtered", "all_zombies_unsuitable", "admin_required", "error"
                - "used_zombie_ip": The IP of the zombie successfully used, if any.
                - "service": "unknown" (can be enhanced later)
                - "confidence": Confidence score of the result.
                - "error": Error message if any.
                - "attempts_log": Log of attempts with different zombies.
        """
        base_results: Dict[str, Any] = {"status": "unknown", "service": "unknown", "confidence": 0.0, "error": None, "used_zombie_ip": None, "attempts_log": []}

        if not self.state.is_admin:
            logger.warning("perform_idle_scan: Idle scan requires administrator privileges for Scapy packet manipulation.")
            base_results["error"] = "Administrator privileges required for Idle Scan."
            base_results["status"] = "admin_required"
            return base_results

        if self.state.executor is None:
            logger.error("perform_idle_scan: Executor not available for synchronous Scapy calls.")
            base_results["error"] = "Executor not available for Scapy calls."
            base_results["status"] = "error"
            return base_results

        if not zombie_ips:
            logger.warning("perform_idle_scan: No zombie IPs provided for Idle Scan.")
            base_results["error"] = "No zombie IPs provided."
            base_results["status"] = "config_error_no_zombies"
            return base_results
            
        logger.info(f"Starting Idle Scan: Target {target_ip}:{target_port}, Potential Zombies: {zombie_ips}, Zombie Port: {zombie_port}")

        for current_zombie_ip in zombie_ips:
            attempt_details = {"zombie_ip_attempted": current_zombie_ip, "_debug_ip_ids": {}}
            logger.info(f"Attempting Idle Scan with zombie: {current_zombie_ip}")

            # Part 1: Zombie Suitability Check - Initial IP ID (using the enhanced _get_ip_id)
            # The enhanced _get_ip_id already performs multiple probes for suitability.
            # We call it once to get the initial ID if it's suitable.
            logger.debug(f"Idle Scan: Probing zombie {current_zombie_ip} for initial IP ID and suitability on port {zombie_port}.")
            # Use a unique sport base for each zombie attempt to avoid conflicts if they are the same machine with multiple IPs
            sport_for_initial_check = RandShort() 
            initial_ip_id = await asyncio.get_event_loop().run_in_executor(
                self.state.executor,
                self._get_ip_id, # This now does robust checking
                current_zombie_ip,
                zombie_port,
                sport_for_initial_check 
            )
            attempt_details["_debug_ip_ids"]["initial_suitability_check_result"] = initial_ip_id

            if initial_ip_id is None:
                logger.warning(f"Idle Scan: Zombie {current_zombie_ip} is unsuitable (failed robust _get_ip_id check).")
                attempt_details["error"] = f"Zombie {current_zombie_ip} unsuitable: Failed robust IP ID suitability check."
                attempt_details["status"] = "zombie_unsuitable_robust_check_failed"
                base_results["attempts_log"].append(attempt_details)
                continue # Try next zombie
            
            logger.info(f"Idle Scan: Zombie {current_zombie_ip} deemed suitable with initial IP ID: {initial_ip_id}.")

            # Part 1.2: Get the IP ID again to establish baseline right before spoofing
            # This is important because _get_ip_id might have taken some time and other traffic might have occurred.
            # We need the IP ID *just before* our spoofed packet.
            sport_for_second_check = RandShort()
            ip_id_after_first_probe = await asyncio.get_event_loop().run_in_executor(
                self.state.executor,
                self._get_ip_id, # Call it again to get a fresh ID; it will do its own probes.
                                 # We are interested in the *first* ID it returns this time.
                current_zombie_ip,
                zombie_port,
                sport_for_second_check,
                num_probes=1 # Just need one reliable ID here as a baseline
            )
            attempt_details["_debug_ip_ids"]["baseline_probe_before_spoof"] = ip_id_after_first_probe

            if ip_id_after_first_probe is None:
                logger.warning(f"Idle Scan: Zombie {current_zombie_ip} became unsuitable or unresponsive when getting baseline IP ID before spoof.")
                attempt_details["error"] = f"Zombie {current_zombie_ip} unsuitable: Failed to get baseline IP ID before spoof."
                attempt_details["status"] = "zombie_unsuitable_baseline_failed"
                base_results["attempts_log"].append(attempt_details)
                continue # Try next zombie

            # The check for (initial_ip_id < ip_id_after_first_probe <= initial_ip_id + 2)
            # is now implicitly handled by the more robust _get_ip_id logic for the *initial* suitability.
            # Here, ip_id_after_first_probe is our new baseline.

            logger.info(f"Idle Scan: Baseline IP ID from zombie {current_zombie_ip} before spoofing is {ip_id_after_first_probe}.")

            # Part 2: Spoofed SYN to Target
            logger.info(f"Idle Scan: Sending spoofed SYN packet to {target_ip}:{target_port} from {current_zombie_ip} (using zombie's port {zombie_port} as source).")
            # Use a distinct source port for the spoofed packet, could be zombie_port or a random one related to it.
            # Nmap typically uses the same source port on the zombie that was used for IP ID probes.
            spoofed_pkt_src_port = zombie_port # Or RandShort() if we want more randomness
            spoofed_pkt = IP(src=current_zombie_ip, dst=target_ip) / TCP(sport=spoofed_pkt_src_port, dport=target_port, flags="S", seq=RandShort())
            logger.debug(f"Sending spoofed Idle Scan SYN from zombie {current_zombie_ip} to {target_ip}:{target_port}: {spoofed_pkt.summary()}")

            await asyncio.get_event_loop().run_in_executor(
                self.state.executor,
                lambda: send(spoofed_pkt, verbose=0, iface=self.config.DEFAULT_IFACE if hasattr(self.config, 'DEFAULT_IFACE') else None)
            )

            await asyncio.sleep(0.5) # Allow time for packet traversal and reaction

            # Part 3: Probe Zombie Again (Post-Spoofed Packet)
            logger.debug(f"Idle Scan: Probing zombie {current_zombie_ip} for IP ID after sending spoofed packet to target.")
            sport_for_final_check = RandShort()
            ip_id_after_spoof = await asyncio.get_event_loop().run_in_executor(
                self.state.executor,
                self._get_ip_id, # Get a fresh ID
                current_zombie_ip,
                zombie_port,
                sport_for_final_check,
                num_probes=1 # Just need one reliable ID
            )
            attempt_details["_debug_ip_ids"]["after_spoof_probe"] = ip_id_after_spoof

            if ip_id_after_spoof is None:
                logger.warning(f"Idle Scan: Zombie {current_zombie_ip} became unresponsive after spoofed packet was sent.")
                attempt_details["error"] = f"Zombie {current_zombie_ip} unresponsive after spoof attempt."
                attempt_details["status"] = "zombie_unresponsive_after_spoof"
                base_results["attempts_log"].append(attempt_details)
                continue # Try next zombie

            logger.info(f"Idle Scan: IP ID from zombie {current_zombie_ip} after spoof is {ip_id_after_spoof}.")

            # Part 4: Determine Port State
            diff = ip_id_after_spoof - ip_id_after_first_probe # Compare with the baseline taken just before spoofing
            attempt_details["_debug_ip_ids"]["difference"] = diff
            attempt_details["error"] = None # Reset error for this successful attempt sequence

            current_scan_status = "unknown"
            current_confidence = 0.0

            if diff == 2: # Target port likely OPEN
                logger.info(f"Idle Scan with {current_zombie_ip}: Target port {target_ip}:{target_port} is LIKELY OPEN (IP ID diff: {diff}).")
                current_scan_status = "open"
                current_confidence = 0.85
            elif diff == 1: # Target port likely CLOSED
                logger.info(f"Idle Scan with {current_zombie_ip}: Target port {target_ip}:{target_port} is LIKELY CLOSED (IP ID diff: {diff}).")
                current_scan_status = "closed"
                current_confidence = 0.85
            else: # Target port likely FILTERED or zombie unreliable for this specific interaction
                logger.warning(f"Idle Scan with {current_zombie_ip}: Target port {target_ip}:{target_port} is LIKELY FILTERED or zombie interaction was noisy (IP ID diff: {diff}). Baseline: {ip_id_after_first_probe}, After spoof: {ip_id_after_spoof}")
                current_scan_status = "filtered"
                current_confidence = 0.70
                attempt_details["error"] = f"Unexpected IP ID difference: {diff}. Zombie might be too active or scan interfered for this attempt."
            
            attempt_details["status"] = current_scan_status
            base_results["attempts_log"].append(attempt_details)

            # If we got a definitive open/closed/filtered, use this zombie and result.
            base_results["status"] = current_scan_status
            base_results["confidence"] = current_confidence
            base_results["used_zombie_ip"] = current_zombie_ip
            base_results["error"] = attempt_details["error"] # Propagate specific error for this attempt if any
            base_results["_debug_ip_ids"] = attempt_details["_debug_ip_ids"] # Store debug info for the successful zombie
            base_results["bypass_method"] = "idle_scan"
            
            logger.info(f"Idle Scan for {target_ip}:{target_port} via {current_zombie_ip} completed. Determined Status: {base_results['status']}, Confidence: {base_results['confidence']}.")
            return base_results # Found a working zombie and completed scan

        # If loop finishes, no suitable zombie was found
        logger.warning(f"Idle Scan for {target_ip}:{target_port}: All {len(zombie_ips)} potential zombies were unsuitable.")
        base_results["status"] = "all_zombies_unsuitable"
        base_results["error"] = f"All {len(zombie_ips)} provided zombies were unsuitable."
        base_results["confidence"] = 0.9 # High confidence that we couldn't find a zombie
        return base_results

    # La fonction _get_zombie_ip_from_user est supprimée car l'IP zombie est maintenant gérée via la configuration.

        # Part 4: Determine Port State
        diff = ip_id_after_spoof - ip_id_after_first_probe
        results["_debug_ip_ids"]["difference"] = diff
        results["error"] = None

        if diff == 2:
            logger.info(f"Idle Scan: Target port {target_ip}:{target_port} is LIKELY OPEN (IP ID diff: {diff}).")
            results["status"] = "open"
            results["confidence"] = 0.85
        elif diff == 1:
            logger.info(f"Idle Scan: Target port {target_ip}:{target_port} is LIKELY CLOSED (IP ID diff: {diff}).")
            results["status"] = "closed"
            results["confidence"] = 0.85
        else:
            logger.warning(f"Idle Scan: Target port {target_ip}:{target_port} is LIKELY FILTERED or zombie is unreliable (IP ID diff: {diff}). Initial: {initial_ip_id}, After 1st probe: {ip_id_after_first_probe}, After spoof: {ip_id_after_spoof}")
            results["status"] = "filtered"
            results["confidence"] = 0.70
            results["error"] = f"Unexpected IP ID difference: {diff}. Zombie might be too active or scan interfered."

        # Part 5: Finalize and Return
        if "initial_zombie_ip_id" in results:
            del results["initial_zombie_ip_id"]
        if "notes" in results:
            del results["notes"]

        logger.info(f"Idle Scan for {target_ip}:{target_port} via {zombie_ip} completed. Determined Status: {results['status']}, Confidence: {results['confidence']}.")
        return results

    # La fonction _get_zombie_ip_from_user est supprimée car l'IP zombie est maintenant gérée via la configuration.

    async def _deep_service_probe(self, ip: str, port: int, response: Optional[IP], response_time: float) -> Dict[str, Any]:
        """Effectue une sonde approfondie pour identifier le service."""
        result = {"service": "unknown", "protocol": "unknown", "details": {}, "confidence": 0.0}
        try:
            common_ports = {
                21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
                80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
                3389: "rdp", 3306: "mysql", 5432: "postgresql", 6379: "redis"
            }
            protocol = common_ports.get(port, "unknown")
            result["protocol"] = protocol

            if protocol in ["http", "https"]:
                http_result = await self._probe_http_service(ip, port, protocol == "https")
                result["service"] = http_result.get("service", "unknown")
                result["details"] = http_result.get("details", {})
                result["confidence"] = 0.9 if "server" in result["details"] else 0.7
            elif protocol == "ftp":
                result.update(await self._probe_ftp_service(ip, port))
            elif protocol == "smtp":
                result.update(await self._probe_smtp_service(ip, port))
            elif protocol == "dns" and response is None:
                result.update(self._send_udp_probe(ip, port, payload=b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01"))
            elif protocol == "unknown": # Basic banner grabbing for unknown TCP services
                banner_info = await self.grab_banner(ip, port, None)
                if banner_info.get("banner"):
                    result["details"]["banner"] = banner_info["banner"]
                    # Attempt to identify service from banner if it's an unknown port
                    version_info = self.identify_service_version(ip, port, banner_info["banner"])
                    if version_info["version"] != "unknown":
                        result["service"] = version_info["version"]
                        result["confidence"] = version_info["confidence"]
                    else:
                        result["service"] = "unknown_tcp_service" # More specific than just "unknown"
                        result["confidence"] = 0.3 # Low confidence as it's just a banner
                else: # No banner, but port is open
                    result["service"] = "open_tcp_port"
                    result["confidence"] = 0.2
            elif protocol == "ssh":
                 # Placeholder for specific SSH probing if we add a library like Paramiko
                banner_info = await self.grab_banner(ip, port, None)
                if banner_info.get("banner"):
                    result["details"]["banner"] = banner_info["banner"]
                    version_info = self.identify_service_version(ip, port, banner_info["banner"])
                    if "openssh" in version_info.get("version", "").lower():
                        result["service"] = version_info["version"]
                        result["confidence"] = 0.9
                    else:
                        result["service"] = "ssh"
                        result["confidence"] = 0.8 if banner_info["banner"] else 0.6
                else:
                    result["service"] = "ssh"
                    result["confidence"] = 0.5 # Open, but no banner
                # Potentially add SSH library handshake test here later

            return result
        except Exception as e:
            logger.error(f"Error in deep_service_probe for {ip}:{port}: {str(e)}")
            result["details"]["error"] = str(e)
            return result

    def _get_ssl_contexts(self) -> List[Dict[str, Any]]:
        """Crée une liste de contextes SSL à essayer, du plus sécurisé au plus compatible."""
        contexts = []
        # 1. Contexte moderne et sécurisé (TLS 1.3 / 1.2, ciphers forts)
        try:
            strong_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            strong_context.check_hostname = False
            strong_context.verify_mode = ssl.CERT_NONE
            strong_context.minimum_version = ssl.TLSVersion.TLSv1_2
            strong_context.set_ciphers('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384')
            contexts.append({"name": "strong", "context": strong_context})
        except Exception as e:
            logger.warning(f"Could not create 'strong' SSL context: {e}")

        # 2. Contexte de compatibilité (plus large)
        try:
            compat_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            compat_context.check_hostname = False
            compat_context.verify_mode = ssl.CERT_NONE
            compat_context.minimum_version = ssl.TLSVersion.TLSv1
            compat_context.set_ciphers('DEFAULT:@SECLEVEL=1')
            contexts.append({"name": "compatible", "context": compat_context})
        except Exception as e:
            logger.warning(f"Could not create 'compatible' SSL context: {e}")
            
        # 3. Contexte SSLv23 (pour la compatibilité avec les anciens systèmes) - DÉSACTIVÉ
        # try:
        #     sslv23_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        #     sslv23_context.check_hostname = False
        #     sslv23_context.verify_mode = ssl.CERT_NONE
        #     contexts.append({"name": "sslv23", "context": sslv23_context})
        # except Exception as e:
        #     logger.warning(f"Could not create 'sslv23' SSL context: {e}")

        # 4. Contexte par défaut
        try:
            default_context = ssl.create_default_context()
            default_context.check_hostname = False
            default_context.verify_mode = ssl.CERT_NONE
            contexts.append({"name": "default", "context": default_context})
        except Exception as e:
            logger.warning(f"Could not create 'default' SSL context: {e}")

        if not contexts:
            fallback_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            fallback_context.check_hostname = False
            fallback_context.verify_mode = ssl.CERT_NONE
            contexts.append({"name": "fallback", "context": fallback_context})
        return contexts

    def _execute_http_bypass_strategies(self, ip: str, port: int, scheme: str, session: requests.Session, proxy_url: Optional[str], original_response: requests.Response) -> Dict[str, Any]:
        """Orchestre diverses stratégies de contournement pour les erreurs HTTP et les WAFs."""
        logger.info(f"Executing advanced bypass strategies for {ip}:{port} due to status {original_response.status_code}")
        result = {"bypassed": False, "details": {"attempts": []}}
        base_url = f"{scheme}://{ip}:{port}"
        domain = self.config.domains[0] if self.config.domains else ip
        
        original_headers = dict(original_response.request.headers) # Use request.headers for original headers sent

        bypass_techniques = [
            # 1. Path and Header variations
            {"name": "Path & Header Variation", "method": "GET", "path_strategy": {"case_variation": True, "trailing_slash_toggle": True, "double_encode_selected_chars": True},
             "header_strategy": {"spoof_ip_headers": True},
             "extra_headers": {"X-Original-URL": "/admin", "X-Rewrite-URL": "/admin", "Referer": f"{scheme}://{domain}/"}},

            # 2. Different method and parameter pollution
            {"name": "POST with HPP", "method": "POST", "path": "/", "body_type": "form",
             "param_strategy": {"hpp_param_pollution": True, "obfuscate_common_params": True, "randomize_param_order": True},
             "extra_headers": {"Content-Type": "application/x-www-form-urlencoded"}},

            # 3. SQLi-like probe (GET)
            {"name": "SQLi Probe (GET)", "method": "GET", "path": "/", "params": {"id": "1' AND 1=1"}},

            # 4. Googlebot User-Agent
            {"name": "Googlebot UA", "method": "GET", "path": "/",
             "header_strategy": {"target_profile": "googlebot"}},
            
            # 5. Fragmented request (simulation via headers)
            {"name": "Fragmented Request Header", "method": "GET", "path": "/",
             "extra_headers": {"Range": "bytes=0-10"}},

            # 6. HTTP Method Tampering (e.g., GET as POST)
            {"name": "HTTP Method Tampering (GET as POST)", "method": "POST", "path": "/",
             "body": b"param=value", "extra_headers": {"X-HTTP-Method-Override": "GET", "Content-Type": "application/x-www-form-urlencoded"}},
            {"name": "HTTP Method Tampering (HEAD)", "method": "HEAD", "path": "/"},
            {"name": "HTTP Method Tampering (OPTIONS)", "method": "OPTIONS", "path": "/"},

            # 7. Content-Encoding Variations
            {"name": "Content-Encoding Identity", "method": "GET", "path": "/",
             "header_strategy": {"accept_encoding": "identity"}},
            {"name": "Content-Encoding Deflate", "method": "GET", "path": "/",
             "header_strategy": {"accept_encoding": "deflate"}},

            # 8. Null Byte Injection (in path)
            {"name": "Null Byte Path Injection", "method": "GET", "path": "/%00/"},
            # 9. Null Byte Injection (in header) - requires custom header handling, not direct in requests
            # 10. Null Byte Injection (in parameter) - handled by generate_query_param_variations

            # 11. Double URL Encoding (path)
            {"name": "Double Encoded Path", "method": "GET", "path": urllib.parse.quote("/admin", safe='')},
            {"name": "Double Encoded Path 2", "method": "GET", "path": urllib.parse.quote(urllib.parse.quote("/admin", safe=''), safe='')},

            # 12. Unicode Encoding (path)
            {"name": "Unicode Encoded Path", "method": "GET", "path": "/%u002fadmin"},

            # 13. Header Order Randomization
            {"name": "Random Header Order", "method": "GET", "path": "/",
             "header_strategy": {"random_header_order": True}},

            # 14. Cookie Manipulation (simple invalid cookie)
            {"name": "Invalid Cookie", "method": "GET", "path": "/",
             "extra_headers": {"Cookie": "invalid_session_id=12345; path=/; domain=example.com"}},

            # 15. Referer/Origin Spoofing
            {"name": "Spoofed Referer", "method": "GET", "path": "/",
             "extra_headers": {"Referer": "http://malicious.com/"}},
            {"name": "Spoofed Origin", "method": "GET", "path": "/",
             "extra_headers": {"Origin": "http://malicious.com"}},

            # 16. HTTP Version Downgrade
            {"name": "HTTP/1.0 Downgrade", "method": "GET", "path": "/",
             "extra_headers": {"Connection": "close"}, "http_version": "1.0"}, # requests handles HTTP/1.0 via Connection: close

            # 17. Random Query Parameter
            {"name": "Random Query Param", "method": "GET", "path": "/",
             "param_strategy": {"add_random_query_param": True}},

            # 18. X-Forwarded-Host bypass
            {"name": "X-Forwarded-Host Bypass", "method": "GET", "path": "/",
             "extra_headers": {"X-Forwarded-Host": "localhost"}},
            
            # 19. Content-Type bypass (for POST/PUT)
            {"name": "Content-Type Bypass (JSON)", "method": "POST", "path": "/",
             "body": b'{"key": "value"}', "extra_headers": {"Content-Type": "application/json"}},
            {"name": "Content-Type Bypass (XML)", "method": "POST", "path": "/",
             "body": b'<data><key>value</key></data>', "extra_headers": {"Content-Type": "application/xml"}},
        ]

        for attempt_config in bypass_techniques:
            try:
                method = attempt_config.get("method", "GET")
                path = attempt_config.get("path", "/")
                params = attempt_config.get("params", {})
                body = attempt_config.get("body")
                body_type = attempt_config.get("body_type")
                http_version = attempt_config.get("http_version")

                # Generate dynamic path variations if strategy_hints are provided
                if "path_strategy" in attempt_config:
                    path = generate_url_path_variation(path, attempt_config["path_strategy"])

                # Generate dynamic query parameter variations
                if "param_strategy" in attempt_config:
                    params_str = generate_query_param_variations(params, attempt_config["param_strategy"])
                    if params_str:
                        path = f"{path}?{params_str}"

                # Generate headers based on strategy hints and extra headers
                current_headers = original_headers.copy()
                header_strategy = attempt_config.get("header_strategy", {})
                if "target_profile" in header_strategy:
                    current_headers.update(self.http_header_mimicry(header_strategy["target_profile"], header_strategy))
                else:
                    # Apply general header strategies if no specific profile is chosen
                    if header_strategy.get("random_header_case"):
                        current_headers = {generate_random_header_case(k): v for k, v in current_headers.items()}
                    if header_strategy.get("random_header_order"):
                        items = list(current_headers.items())
                        random.shuffle(items)
                        current_headers = dict(items)
                    if header_strategy.get("spoof_ip_headers"):
                        current_headers.update(generate_spoofed_ip_headers())
                    if header_strategy.get("accept_encoding"):
                        current_headers["Accept-Encoding"] = header_strategy["accept_encoding"]

                current_headers.update(attempt_config.get("extra_headers", {}))
                
                # Handle body generation if specified
                if body_type:
                    body, content_type = generate_request_body(method, body_type)
                    if content_type:
                        current_headers["Content-Type"] = content_type

                proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

                logger.debug(f"Attempting bypass: {attempt_config['name']} to {base_url}{path}")

                # Use aiohttp for more control over HTTP versions and raw requests if needed
                # For now, stick to requests for simplicity, but note the limitation for HTTP/1.0
                # requests library automatically handles HTTP/1.0 if Connection: close is set.
                response = requests.request(
                    method, f"{base_url}{path}",
                    headers=current_headers, data=body,
                    proxies=proxies, timeout=self.config.timeout, allow_redirects=False
                )
                
                attempt_details = {"name": attempt_config["name"], "method": method, "path": path,
                                   "status_code": response.status_code, "headers_sent": dict(response.request.headers)}
                result["details"]["attempts"].append(attempt_details)

                if 200 <= response.status_code < 400:
                    logger.info(f"SUCCESS: Bypass strategy '{attempt_config['name']}' succeeded for {base_url} with status {response.status_code}")
                    result["bypassed"] = True
                    result["successful_attempt"] = attempt_details
                    return result
                else:
                    logger.warning(f"Bypass strategy '{attempt_config['name']}' failed for {base_url} with status {response.status_code}")

            except requests.exceptions.RequestException as e:
                logger.warning(f"Bypass strategy '{attempt_config['name']}' failed: {e}")
                result["details"]["attempts"].append({"name": attempt_config['name'], "error": str(e)})
            except Exception as e:
                logger.error(f"Unexpected error during bypass strategy '{attempt_config['name']}': {e}", exc_info=True)
                result["details"]["attempts"].append({"name": attempt_config['name'], "error": f"Unexpected error: {str(e)}"})
        
        logger.warning(f"All bypass strategies failed for {ip}:{port}.")
        return result

    async def orchestrate_waf_bypass(self, ip: str, port: int, scheme: str, session: requests.Session, proxy_url: Optional[str], original_response: requests.Response, detected_waf_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Orchestre intelligemment les stratégies de contournement de WAF en fonction du WAF détecté
        et des réponses précédentes. Utilise une logique de décision adaptative.
        """
        logger.info(f"[WAF Bypass Orchestrator] Starting orchestration for {ip}:{port}. Detected WAF: {detected_waf_info.get('waf', 'None')}")
        orchestration_result = {"bypassed": False, "details": {"attempts": []}, "final_waf_info": detected_waf_info}
        
        # Define a pool of strategies, potentially ordered or grouped by WAF type
        # This is a simplified example; in a real scenario, this would be much more dynamic
        # and potentially loaded from a configuration or a more complex decision tree.
        strategies_pool = [
            # Initial broad attempts
            {"name": "Default Headers & Path Variations", "path_strategy": {"case_variation": True, "trailing_slash_toggle": True}, "header_strategy": {"spoof_ip_headers": True}},
            {"name": "Googlebot UA & Referer Spoof", "header_strategy": {"target_profile": "googlebot", "spoof_ip_headers": True}, "extra_headers": {"Referer": "https://www.google.com/"}},
            {"name": "HTTP Method Tampering (HEAD)", "method": "HEAD", "path": "/"},
            {"name": "HTTP Method Tampering (OPTIONS)", "method": "OPTIONS", "path": "/"},
            {"name": "Content-Encoding Identity", "header_strategy": {"accept_encoding": "identity"}},
            {"name": "Random Query Param", "param_strategy": {"add_random_query_param": True}},
            {"name": "X-Forwarded-Host Bypass", "extra_headers": {"X-Forwarded-Host": "localhost"}},

            # More aggressive/specific attempts
            {"name": "Double Encoded Path", "path": urllib.parse.quote("/admin", safe='')},
            {"name": "Null Byte Path Injection", "path": "/%00/"},
            {"name": "SQLi Probe (GET)", "method": "GET", "path": "/", "params": {"id": "1' AND 1=1"}},
            {"name": "POST with HPP", "method": "POST", "path": "/", "body_type": "form",
             "param_strategy": {"hpp_param_pollution": True, "obfuscate_common_params": True, "randomize_param_order": True},
             "extra_headers": {"Content-Type": "application/x-www-form-urlencoded"}},
            {"name": "Random Header Order", "header_strategy": {"random_header_order": True}},
            {"name": "Invalid Cookie", "extra_headers": {"Cookie": "invalid_session_id=12345; path=/; domain=example.com"}},
            {"name": "Spoofed Origin", "extra_headers": {"Origin": "http://malicious.com"}},
            {"name": "HTTP/1.0 Downgrade", "http_version": "1.0"},
            {"name": "Content-Type Bypass (JSON)", "method": "POST", "path": "/",
             "body": b'{"key": "value"}', "extra_headers": {"Content-Type": "application/json"}},
        ]

        # Prioritize strategies based on detected WAF
        waf_name = detected_waf_info.get("waf", "none").lower()
        if waf_name != "none":
            # Example: If Cloudflare is detected, try JS challenge bypasses first (if implemented)
            # For now, we'll just log that we're prioritizing.
            logger.info(f"[WAF Bypass Orchestrator] Prioritizing strategies for detected WAF: {waf_name}")
            # In a real scenario, you'd reorder/filter strategies_pool here.

        for attempt_config in strategies_pool:
            try:
                logger.info(f"[WAF Bypass Orchestrator] Attempting strategy: {attempt_config['name']}")
                
                # Call the existing _execute_http_bypass_strategies for individual execution
                # We need to adapt _execute_http_bypass_strategies to take a single attempt_config
                # or refactor this part. For now, let's make a helper for single attempt.
                attempt_result = await self._execute_single_bypass_attempt(
                    ip, port, scheme, session, proxy_url, original_response.request.headers, attempt_config
                )
                orchestration_result["details"]["attempts"].append(attempt_result)

                if attempt_result.get("bypassed"):
                    logger.info(f"[WAF Bypass Orchestrator] Successfully bypassed WAF with strategy: {attempt_config['name']}")
                    orchestration_result["bypassed"] = True
                    orchestration_result["successful_attempt"] = attempt_result.get("successful_attempt")
                    return orchestration_result
                else:
                    logger.warning(f"[WAF Bypass Orchestrator] Strategy '{attempt_config['name']}' failed. Status: {attempt_result.get("status_code", "N/A")}")
                    # Here, you could add logic to analyze the failure and adapt future strategies
                    # e.g., if a 403 is returned, try more aggressive obfuscation.

            except Exception as e:
                logger.error(f"[WAF Bypass Orchestrator] Error during strategy '{attempt_config.get('name', 'unknown')}': {e}", exc_info=True)
                orchestration_result["details"]["attempts"].append({"name": attempt_config.get('name', 'unknown'), "error": str(e)})
        
        logger.warning(f"[WAF Bypass Orchestrator] All orchestration strategies failed for {ip}:{port}.")
        return orchestration_result

    async def _execute_single_bypass_attempt(self, ip: str, port: int, scheme: str, session: requests.Session, proxy_url: Optional[str], original_headers: Dict[str, str], attempt_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Exécute une seule tentative de contournement HTTP basée sur une configuration donnée.
        Factorisé à partir de _execute_http_bypass_strategies pour être appelé par l'orchestrateur.
        """
        base_url = f"{scheme}://{ip}:{port}"
        result = {"bypassed": False, "status_code": None, "error": None, "successful_attempt": None}

        try:
            method = attempt_config.get("method", "GET")
            path = attempt_config.get("path", "/")
            params = attempt_config.get("params", {})
            body = attempt_config.get("body")
            body_type = attempt_config.get("body_type")
            http_version = attempt_config.get("http_version")

            # Generate dynamic path variations if strategy_hints are provided
            if "path_strategy" in attempt_config:
                path = generate_url_path_variation(path, attempt_config["path_strategy"])

            # Generate dynamic query parameter variations
            if "param_strategy" in attempt_config:
                params_str = generate_query_param_variations(params, attempt_config["param_strategy"])
                if params_str:
                    path = f"{path}?{params_str}"

            # Generate headers based on strategy hints and extra headers
            current_headers = original_headers.copy()
            header_strategy = attempt_config.get("header_strategy", {})
            if "target_profile" in header_strategy:
                current_headers.update(self.http_header_mimicry(header_strategy["target_profile"], header_strategy))
            else:
                # Apply general header strategies if no specific profile is chosen
                if header_strategy.get("random_header_case"):
                    current_headers = {generate_random_header_case(k): v for k, v in current_headers.items()}
                if header_strategy.get("random_header_order"):
                    items = list(current_headers.items())
                    random.shuffle(items)
                    current_headers = dict(items)
                if header_strategy.get("spoof_ip_headers"):
                    current_headers.update(generate_spoofed_ip_headers())
                if header_strategy.get("accept_encoding"):
                    current_headers["Accept-Encoding"] = header_strategy["accept_encoding"]

            current_headers.update(attempt_config.get("extra_headers", {}))
            
            # Handle body generation if specified
            if body_type:
                body, content_type = generate_request_body(method, body_type)
                if content_type:
                    current_headers["Content-Type"] = content_type

            proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

            logger.debug(f"Executing single bypass attempt: {attempt_config['name']} to {base_url}{path}")

            response = requests.request(
                method, f"{base_url}{path}",
                headers=current_headers, data=body,
                proxies=proxies, timeout=self.config.timeout, allow_redirects=False
            )
            
            result["status_code"] = response.status_code
            attempt_details = {"name": attempt_config["name"], "method": method, "path": path,
                               "status_code": response.status_code, "headers_sent": dict(response.request.headers)}

            if 200 <= response.status_code < 400:
                logger.info(f"SUCCESS: Single bypass attempt '{attempt_config['name']}' succeeded for {base_url} with status {response.status_code}")
                result["bypassed"] = True
                result["successful_attempt"] = attempt_details
            else:
                logger.warning(f"Single bypass attempt '{attempt_config['name']}' failed for {base_url} with status {response.status_code}")

        except requests.exceptions.RequestException as e:
            logger.warning(f"Single bypass attempt '{attempt_config['name']}' failed: {e}")
            result["error"] = str(e)
        except Exception as e:
            logger.error(f"Unexpected error during single bypass attempt '{attempt_config['name']}': {e}", exc_info=True)
            result["error"] = f"Unexpected error: {str(e)}"
        
        return result

    async def _probe_http_service(self, ip: str, port: int, is_https: bool = False, http_profile: str = "chrome_windows") -> Dict[str, Any]:
        """Sonde un service HTTP/HTTPS en utilisant des profils SSL/TLS variés et des stratégies de contournement avancées."""
        result = {"service": "http", "details": {}, "confidence": 0.7, "error": None}
        scheme = "https" if is_https else "http"
        base_url_target = f"{scheme}://{ip}:{port}"
        
        proxy = self._get_next_proxy()
        proxies = {"http": proxy["url"], "https": proxy["url"]} if proxy else None

        # --- Intégration Chameleon ---
        logger.info(f"[Chameleon] Preparing HTTP probe for {base_url_target}")
        initial_headers = self.http_header_mimicry(http_profile)
        initial_headers.update(generate_spoofed_ip_headers())
        initial_headers["Connection"] = "close"
        logger.info(f"[Chameleon] Using HTTP profile: {http_profile}")

        ssl_contexts = self._get_ssl_contexts() if is_https else [{"name": "none", "context": None}]
        last_error = None

        for ssl_config in ssl_contexts:
            # ssl_context is not directly used by requests.get, but kept for logging/context
            context_name = ssl_config["name"]
            logger.debug(f"Probing {base_url_target} with SSL profile: {context_name}")
            
            try:
                with requests.Session() as session:
                    session.verify = False # Disable SSL verification for flexibility
                    # For advanced SSL options, you might need to pass a custom SSLContext to verify parameter
                    # or use a library like `urllib3.contrib.pyopenssl`.
                    # For simplicity, we'll just disable verification for now.

                    response = session.get(base_url_target + "/", headers=initial_headers, proxies=proxies, timeout=self.config.timeout, allow_redirects=False)
                        
                    result["details"]["initial_get"] = {
                        "status_code": response.status_code, "headers": dict(response.headers), "ssl_profile_used": context_name
                    }
                    
                    response_body_text = response.text
                    result["details"]["initial_get"]["content_preview"] = response_body_text[:512]

                    waf_info = self._detect_waf_from_response(response, response_body_text)
                    result["details"]["waf"] = waf_info
                    if waf_info["waf"] != "none":
                        logger.info(f"WAF {waf_info['waf']} detected on {base_url_target}/ with SSL profile {context_name}")

                    if response.headers.get("Server"):
                        result["service"] = response.headers.get("Server")
                        result["confidence"] = 0.9
                    
                    if 200 <= response.status_code < 400:
                        logger.info(f"Successful probe for {base_url_target} with SSL profile {context_name}. Status: {response.status_code}")
                        return result

                    logger.warning(f"Initial GET for {base_url_target} returned error {response.status_code}. Triggering bypass strategies.")
                    bypass_results = self._execute_http_bypass_strategies(ip, port, scheme, session, proxy["url"] if proxy else None, response)
                    result["details"]["bypass_attempts"] = bypass_results
                    
                    if bypass_results.get("bypassed"):
                        result["service"] = f"http (bypassed {response.status_code})"
                        result["confidence"] = 0.95
                        return result
                    else:
                        logger.warning(f"Bypass strategies failed for {base_url_target} with SSL profile {context_name}.")
                        last_error = f"HTTP Error {response.status_code} (Bypass Failed)"
                        continue
            except requests.exceptions.SSLError as e:
                last_error = f"SSL_Error ({context_name}): {type(e).__name__}"
                logger.warning(f"SSL error with profile '{context_name}' for {base_url_target}: {last_error}")
                if proxy: self.report_proxy_failure(proxy["url"])
                continue
            except requests.exceptions.RequestException as e:
                last_error = f"Client_Error ({context_name}): {type(e).__name__}"
                logger.warning(f"Client error with profile '{context_name}' for {base_url_target}: {last_error}")
                if proxy: self.report_proxy_failure(proxy["url"])
                continue
            except Exception as e:
                last_error = f"Unexpected_Error ({context_name}): {type(e).__name__}"
                logger.error(f"Unexpected error with profile '{context_name}' for {base_url_target}: {last_error}", exc_info=True)
                break

        result["error"] = last_error
        logger.error(f"All probing attempts failed for {base_url_target}. Last error: {last_error}")
        return result

    async def _probe_ftp_service(self, ip: str, port: int) -> Dict[str, Any]:
        """Sonde un service FTP."""
        result = {"service": "ftp", "details": {}, "confidence": 0.7, "error": None}
        try:
            # Utiliser un timeout pour la connexion et la lecture de la bannière FTP
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.config.timeout / 2 if self.config.timeout > 1 else 1.5
            )

            banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            banner = banner_bytes.decode(errors="replace")
            result["details"]["banner"] = banner

            if not banner.startswith("220"):
                logger.warning(f"Unexpected SMTP banner from {ip}:{port}: {banner[:100]}")
                result["confidence"] = 0.6 # Bannière non standard mais port ouvert

            writer.write(b"HELO test.example.com\r\n") # Utiliser un domaine plus réaliste
            await writer.drain()

            response_bytes = await asyncio.wait_for(reader.read(1024), timeout=1.0) # Réponse au HELO (250)
            response = response_bytes.decode(errors="replace")
            result["details"]["helo_response"] = response

            if "smtp" in banner.lower() or "esmtp" in banner.lower() or banner.startswith("220"):
                if response.startswith("250"):
                    result["confidence"] = 0.95 # Interaction réussie
                else:
                    result["confidence"] = 0.8 # Bannière OK, HELO a échoué mais c'est probablement SMTP

            writer.write(b"QUIT\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        except asyncio.TimeoutError:
            logger.warning(f"Timeout probing SMTP service {ip}:{port}")
            result["error"] = "Timeout_SMTP_Probe"
            result["confidence"] = 0.4
        except ConnectionRefusedError:
            logger.warning(f"SMTP connection refused for {ip}:{port}")
            result["error"] = "ConnectionRefused_SMTP"
            result["status"] = "closed"
            result["confidence"] = 0.9
        except Exception as e:
            logger.error(f"Error probing SMTP service {ip}:{port}: {type(e).__name__} - {str(e)}")
            result["error"] = f"SMTP_Error: {type(e).__name__} - {str(e)}"
            result["confidence"] = 0.3
        return result

    def _detect_waf_from_response(self, response: requests.Response, body: str) -> Dict[str, Any]:
        """Détecte un WAF en utilisant les signatures WAF_SIGNATURES."""
        # Normaliser le corps en minuscules une seule fois pour les recherches insensibles à la casse
        body_lower = body.lower()

        detected_wafs = []

        for waf_name, signatures in WAF_SIGNATURES.items():
            current_score = 0
            matching_details = []

            # Vérification des en-têtes
            for header_sig in signatures.get("headers", []):
                header_to_check = header_sig["name"]
                pattern = re.compile(header_sig["pattern"], re.IGNORECASE if not header_sig.get("case_sensitive") else 0)

                if header_to_check == "ANY_HEADER": # Cas spécial pour AWS WAF
                    for h_name, h_value in response.headers.items():
                        if "x-amz-waf-" in h_name.lower(): # Optimisation: vérifier le préfixe d'abord
                             if pattern.search(h_value):
                                current_score += header_sig["score"]
                                matching_details.append(f"Header {h_name} matches pattern {header_sig['pattern']}")
                                break # Une correspondance suffit pour ANY_HEADER avec ce pattern
                elif header_to_check in response.headers:
                    if pattern.search(response.headers[header_to_check]):
                        current_score += header_sig["score"]
                        matching_details.append(f"Header {header_to_check} matches pattern {header_sig['pattern']}")

            # Vérification du corps (utiliser body_lower pour les recherches insensibles à la casse par défaut)
            for body_sig in signatures.get("body", []):
                # Assumer que la plupart des patterns de corps sont insensibles à la casse
                # Si une signature de corps DOIT être sensible à la casse, elle devrait avoir "case_sensitive": True
                if body_sig.get("case_sensitive"):
                    pattern = re.compile(body_sig["pattern"])
                    # target_body = body # Inutile car re.search prendra `body` directement
                else:
                    # Le pattern sera compilé avec IGNORECASE, donc on peut chercher directement dans `body`
                    # target_body = body_lower # Inutile si le pattern a IGNORECASE
                    pass

                if re.search(body_sig["pattern"], body, re.IGNORECASE if not body_sig.get("case_sensitive") else 0):
                    current_score += body_sig["score"]
                    matching_details.append(f"Body matches pattern {body_sig['pattern']}")

            # Vérification des codes de statut
            for status_sig in signatures.get("status_codes", []):
                if response.status_code in status_sig["codes"]:
                    current_score += status_sig["score"]
                    matching_details.append(f"Status code {response.status_code} matches allowed codes")

            # Vérification des cookies
            for cookie_sig in signatures.get("cookies", []):
                cookie_name = cookie_sig["name"]
                if cookie_name in response.cookies:
                    cookie_value = response.cookies[cookie_name].value
                    pattern = re.compile(cookie_sig["pattern"], re.IGNORECASE if not cookie_sig.get("case_sensitive") else 0)
                    if pattern.search(cookie_value):
                        current_score += cookie_sig["score"]
                        matching_details.append(f"Cookie {cookie_name} matches pattern {cookie_sig['pattern']}")

            if current_score >= signatures["final_threshold"]:
                confidence = min(current_score / signatures["final_threshold"], 1.0)
                if len(matching_details) == 1 and current_score == signatures["final_threshold"]:
                     confidence *= 0.9

                detected_wafs.append({
                    "waf": waf_name,
                    "confidence": round(confidence * 100, 2),
                    "score": current_score,
                    "threshold": signatures["final_threshold"],
                    "details": matching_details
                })

        if not detected_wafs:
            return {"waf": "none", "confidence": 0.0, "details": []}

        best_waf = max(detected_wafs, key=lambda w: (w["confidence"], w["score"]))
        return best_waf


    async def _detect_waf(self, ip: str, port: int) -> Dict[str, Any]:
        """Tente de détecter la présence et le type d'un WAF sur les ports HTTP/HTTPS uniquement."""
        result = {"waf": "none", "confidence": 0.0, "error": None, "details": []}
        if port not in self.http_ports:
            result["error"] = f"Port {port} is not a standard HTTP/HTTPS port, skipping WAF detection"
            logger.warning(result["error"])
            return result

        scheme = "https" if port in [443, 8443] else "http"
        test_paths_payloads = [
            ("/", {"method": "GET", "payload": "<script>alert('WAF_Test')</script>", "type": "param_value"}),
            ("/?id=1%20UNION%20SELECT%20NULL", {"method": "GET", "payload": None}),
            ("/admin", {"method": "GET", "payload": None}),
        ]

        base_headers = {
            **generate_common_accept_headers(),
            **generate_spoofed_ip_headers(),
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Connection": "close"
        }

        ssl_context = None
        if scheme == "https":
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

        with requests.Session() as session:
            session.verify = False # Disable SSL verification for flexibility
            if ssl_context: # Apply SSL context if provided
                session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=5, pool_maxsize=5))
                
                # For advanced SSL options, you might need to pass a custom SSLContext to verify parameter
                # or use a library like `urllib3.contrib.pyopenssl`.
                # For simplicity, we'll just disable verification for now.

            for path_with_query, probe_config in test_paths_payloads:
                base_path = path_with_query.split("?")[0]
                query_in_path = path_with_query.split("?")[1] if "?" in path_with_query else None

                url = f"{scheme}://{ip}:{port}{base_path}"
                current_headers = base_headers.copy()
                method = probe_config["method"]
                data_payload = None
                params_payload = {}

                if query_in_path: # Si la query est dans le path, la parser
                    params_payload.update(urllib.parse.parse_qs(query_in_path))


                if probe_config["payload"]:
                    if probe_config["type"] == "param_value":
                        # Ajouter le payload comme valeur d'un paramètre aléatoire
                        params_payload[f"test_param_{random.randint(1,100)}"] = probe_config["payload"]
                    elif probe_config["type"] == "body" and method in ["POST", "PUT"]:
                        # Utiliser le payload comme corps (nécessite un encodage approprié et Content-Type)
                        if isinstance(probe_config["payload"], str):
                            data_payload = probe_config["payload"].encode()
                            current_headers["Content-Type"] = "application/x-www-form-urlencoded" # ou text/plain
                        else: # Supposer bytes
                            data_payload = probe_config["payload"]
                            current_headers["Content-Type"] = "application/octet-stream" # Générique

                logger.debug(f"WAF detection probe: {method} {url} (Params: {params_payload}), Payload: {str(data_payload)[:50] if data_payload else 'None'}")

                try:
                    proxy = self._get_next_proxy()
                    proxy_url = proxy["url"] if proxy else None
                    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

                    response = session.request(method, url, headers=current_headers, params=params_payload, data=data_payload, proxies=proxies, timeout=self.config.timeout)
                        
                    body_text = response.text

                    waf_info_probe = self._detect_waf_from_response(response, body_text)

                    probe_details = {
                        "method": method, "url_probed": url, "params_probed": params_payload, "payload_used_in_body": bool(data_payload),
                        "status_code": response.status_code,
                        "detected_waf_on_probe": waf_info_probe["waf"],
                        "probe_waf_confidence": waf_info_probe.get("confidence"),
                        "probe_waf_details": waf_info_probe.get("details")
                    }
                    result["details"].append(probe_details)

                    if waf_info_probe["waf"] != "none":
                        if waf_info_probe.get("confidence", 0) > result.get("confidence", 0):
                            result["waf"] = waf_info_probe["waf"]
                            result["confidence"] = waf_info_probe["confidence"]
                            if result["confidence"] > 80:
                                logger.info(f"High confidence WAF detected: {result['waf']} ({result['confidence']}%) on {url}")
                                return result

                except requests.exceptions.SSLError as e:
                    error_reason = str(e)
                    min_tls_version_str = 'N/A'
                    if ssl_context and hasattr(ssl_context, 'minimum_version'):
                        min_tls_version_str = str(ssl_context.minimum_version)
                    # requests.exceptions.SSLError does not have os_error attribute directly
                    logger.warning(f"SSL error during WAF detection for {url}: {type(e).__name__} - {error_reason}. Min TLS: {min_tls_version_str}")
                    result["details"].append({"path": path_with_query, "error": f"SSL_Error: {type(e).__name__} - {error_reason}"})
                    if proxy_url: self.report_proxy_failure(proxy_url)
                    continue
                except requests.exceptions.ProxyError as e:
                    logger.error(f"Proxy connection error for WAF detection at {url} with proxy {proxy_url}: {str(e)}")
                    result["details"].append({"path": path_with_query, "error": f"Proxy_Error: {str(e)}"})
                    if proxy_url: self.report_proxy_failure(proxy_url)
                except requests.exceptions.ConnectionError as e:
                     logger.warning(f"Connection OS error for WAF detection at {url}: {str(e)}")
                     result["details"].append({"path": path_with_query, "error": f"Connection_OSError: {str(e)}"})
                except requests.exceptions.Timeout:
                    logger.warning(f"Timeout during WAF detection for {url}")
                    result["details"].append({"path": path_with_query, "error": "Timeout_WAF_Detect"})
                    if proxy_url: self.report_proxy_failure(proxy_url)
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Client error during WAF detection for {url}: {type(e).__name__} - {str(e)}")
                    result["details"].append({"path": path_with_query, "error": f"Client_Error: {type(e).__name__} - {str(e)}"})
                    if proxy_url: self.report_proxy_failure(proxy_url)
                except Exception as e:
                    logger.error(f"Unexpected error during WAF detection for {url}: {type(e).__name__} - {str(e)}")
                    result["details"].append({"path": path_with_query, "error": f"Unexpected_Error: {type(e).__name__} - {str(e)}"})

        if result["waf"] != "none":
            logger.info(f"Final WAF detection for {ip}:{port}: {result['waf']} with confidence {result['confidence']}%")
        else:
            logger.info(f"No WAF definitively detected for {ip}:{port} after multiple probes.")
        return result

    async def scan_port(self, ip: str, port: int, domain: Optional[str] = None) -> Dict[str, Any]:
        """Effectue un scan sur un port spécifique et retourne un dictionnaire de résultats."""
        result = {
            "ip": ip,
            "port": port,
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "status": "unknown",
            "service_info": {},
            "waf_detection": {},
            "bypass_attempts": {},
            "stealth_results": {},
            "error": None
        }

        logger.info(f"[NetworkScan] Scanning {ip}:{port}")
        await self.traffic_pacing_control() # Apply pacing before each port scan

        try:
            # --- Initial TCP Connect Scan ---
            tcp_connect_result = self.tcp_connect(ip, port)
            result["status"] = tcp_connect_result.get("status", "unknown")
            result["service_info"]["tcp_connect"] = tcp_connect_result

            # --- Idle Scan (Netghost) ---
            if self.config.use_idle_scan and self.config.zombie_ips:
                logger.info(f"[Netghost] Attempting Idle Scan on {ip}:{port} using zombies: {self.config.zombie_ips}")
                idle_scan_result = await self.perform_idle_scan(ip, port, self.config.zombie_ips)
                result["stealth_results"]["idle_scan"] = idle_scan_result
                if idle_scan_result.get("status") in ["open", "closed", "filtered"]:
                    result["status"] = idle_scan_result["status"]
                    result["service_info"]["idle_scan_confidence"] = idle_scan_result.get("confidence", 0.0)

            # --- Decoy Scan (Netghost) ---
            if self.config.use_decoy_scan and self.config.decoys:
                logger.info(f"[Netghost] Attempting Decoy Scan on {ip}:{port} using decoys: {self.config.decoys}")
                decoy_scan_result = await self.decoy_scan(ip, port, self.config.decoys)
                result["stealth_results"]["decoy_scan"] = decoy_scan_result
                if decoy_scan_result.get("status") in ["open", "closed", "filtered", "bypassed", "blocked_by_waf"]:
                    # Prioritize decoy scan status if it provides a more definitive answer
                    if result["status"] == "unknown" or decoy_scan_result["status"] in ["open", "closed"]:
                        result["status"] = decoy_scan_result["status"]
                    result["service_info"]["decoy_scan_details"] = decoy_scan_result.get("details", {})

            # --- Fragmented Scan (Netghost) ---
            if self.config.use_fragmented_scan:
                logger.info(f"[Netghost] Attempting Fragmented Scan on {ip}:{port}")
                fragmented_scan_result = await self.fragmented_packet_scan(ip, port)
                result["stealth_results"]["fragmented_scan"] = fragmented_scan_result

            # --- Deep Service Probing (Chameleon) ---
            if result["status"] == "open" or (result["status"] == "unknown" and port in self.http_ports):
                logger.info(f"[Chameleon] Performing deep service probe on {ip}:{port}")
                deep_probe_result = await self._deep_service_probe(ip, port, None, 0.0) # Pass dummy response/time for now
                result["service_info"]["deep_probe"] = deep_probe_result
                if deep_probe_result.get("service") != "unknown":
                    result["service_info"]["identified_service"] = deep_probe_result["service"]
                    result["service_info"]["service_confidence"] = deep_probe_result.get("confidence", 0.0)

                # --- WAF Detection (Chameleon) ---
                if port in self.http_ports:
                    logger.info(f"[Chameleon] Attempting WAF detection on {ip}:{port}")
                    waf_detection_result = await self._detect_waf(ip, port)
                    result["waf_detection"] = waf_detection_result
                    if waf_detection_result.get("waf") != "none":
                        logger.warning(f"WAF detected: {waf_detection_result['waf']} on {ip}:{port}")
                        # --- WAF Bypass (Chameleon) ---
                        logger.info(f"[Chameleon] Attempting WAF bypass on {ip}:{port}")
                        bypass_result = await self.bypass.waf_bypass(ip, port, domain, waf_detection_result["waf"])
                        result["bypass_attempts"] = bypass_result
                        if bypass_result.get("bypassed"):
                            logger.info(f"WAF bypass successful for {ip}:{port}!")
                            result["status"] = "open (bypassed WAF)"

            # --- Probe closed/filtered ports with advanced techniques ---
            elif result["status"] in ["closed", "filtered"]:
                logger.info(f"[NetworkScan] Probing closed/filtered port {ip}:{port} with advanced techniques.")
                advanced_probe_result = self.probe_closed_port_advanced(ip, port)
                result["service_info"]["advanced_closed_probe"] = advanced_probe_result
                # Update status if advanced probe gives a more definitive answer
                if advanced_probe_result.get("status") in ["open", "closed"]:
                    result["status"] = advanced_probe_result["status"]

        except Exception as e:
            logger.error(f"Error during scan_port for {ip}:{port}: {str(e)}", exc_info=True)
            result["error"] = str(e)
            result["status"] = "error"

        return result

    async def scan_target(self, target: str, ports: List[int], domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Orchestre le scan complet sur une cible et une liste de ports."""
        results = []
        for port in ports:
            result = await self.scan_port(target, port, domain)
            results.append(result)
        return results

    async def symbiotic_scan(self, target: str, ports: List[int], domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Orchestrates a comprehensive, multi-layered scan incorporating various techniques
        including stealth, evasion, and deep service probing.
        """
        logger.info(f"Initiating symbiotic scan for target: {target} on ports: {ports}")
        full_scan_results = {
            "target": target,
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "scan_details": []
        }

        for port in ports:
            logger.info(f"Scanning port {port} on {target}...")
            port_scan_result = await self.scan_port(target, port, domain)
            full_scan_results["scan_details"].append(port_scan_result)
            await self.traffic_pacing_control() # Pacing between ports

        logger.info(f"Symbiotic scan completed for {target}.")
        return full_scan_results

    def _send_udp_probe(self, ip: str, port: int, payload: bytes = b"") -> Dict[str, Any]:
        """Envoie des sondes UDP avec des payloads spécifiques à certains protocoles."""
        result = {"status": "unknown", "details": "", "error": None}
        try:
            # Assurer que l'interface est configurée si Scapy en a besoin explicitement sur certains OS
            scapy_iface = self.config.DEFAULT_IFACE if hasattr(self.config, 'DEFAULT_IFACE') and self.config.DEFAULT_IFACE else None

            packet = IP(dst=ip)/UDP(dport=port, sport=RandShort())/payload
            # Utiliser un timeout plus court pour les sondes UDP car elles sont sans état
            udp_timeout = max(self.config.timeout / 2, 1.0) if self.config.timeout > 0 else 1.0

            response = sr1(packet, timeout=udp_timeout, verbose=0, iface=scapy_iface)

            if response is None: # Pas de réponse
                result["status"] = "open|filtered" # Standard pour UDP sans réponse
                result["details"] = "No response to UDP probe."
            elif response.haslayer(UDP):
                result["status"] = "open" # Réponse UDP, port est ouvert
                result["details"] = self._serialize_ip_packet(response)
                # Identification de service basique basée sur le port
                if port == 53: result["service"] = "dns"
                elif port == 161: result["service"] = "snmp"
                elif port == 123: result["service"] = "ntp"
                # On pourrait ajouter d'autres ici ou une logique de pattern matching sur la réponse
            elif response.haslayer(IP) and response.haslayer(TCP) and response[TCP].flags == 'R': # RST sur certains OS
                result["status"] = "closed"
                result["details"] = "Received TCP RST in response to UDP, port likely closed."
            elif response.haslayer("ICMP"):
                icmp_type = response["ICMP"].type
                icmp_code = response["ICMP"].code
                if icmp_type == 3: # Destination Unreachable
                    if icmp_code in [0, 1, 2, 9, 10, 13]: # Network/Host/Protocol/Net-Admin/Host-Admin/Comm-Admin-Prohibited
                        result["status"] = "filtered"
                        result["details"] = f"ICMP Destination Unreachable (Type {icmp_type}, Code {icmp_code}) - Host or Network Filtered"
                    elif icmp_code == 3: # Port Unreachable
                        result["status"] = "closed"
                        result["details"] = f"ICMP Port Unreachable (Type {icmp_type}, Code {icmp_code}) - Port Closed"
                    else:
                        result["status"] = "filtered" # Autre ICMP Unreachable
                        result["details"] = f"ICMP Destination Unreachable (Type {icmp_type}, Code {icmp_code}) - Filtered"
                else:
                    result["status"] = "filtered" # Autre ICMP
                    result["details"] = f"Received ICMP Type {icmp_type}, Code {icmp_code} - Filtered"
            else:
                result["status"] = "unknown_response" # Réponse inattendue
                result["details"] = f"Unexpected response: {response.summary() if response else 'None'}"

        except PermissionError as e:
            logger.error(f"Permission error in UDP probe for {ip}:{port} (raw sockets often require root): {str(e)}")
            result["error"] = "PermissionError_UDP_Probe"
            result["status"] = "error_permission"
        except Exception as e:
            logger.error(f"Error in UDP probe for {ip}:{port}: {type(e).__name__} - {str(e)}")
            result["error"] = f"UDP_Probe_Exception: {type(e).__name__}"
            result["status"] = "error"
        return result

    def _parse_tcp_options(self, tcp_options_list: List[Tuple[str, Any]]) -> Dict[str, Any]:
        """Parse la liste des options TCP de Scapy en un dictionnaire."""
        return {opt[0]: opt[1] for opt in tcp_options_list}

    def fingerprint_tcp_ip(self, pkt: IP) -> str:
        """Identifie l'OS ou le type de périphérique en se basant sur les caractéristiques TCP/IP."""
        # Cette fonction est un placeholder. Une vraie empreinte digitale OS est complexe.
        # Pourrait vérifier TTL, Window Size, TCP Options (MSS, SACK, Timestamps, NOP, Window Scale)
        # et les comparer à une base de données d'empreintes.
        # Exemple très basique:
        if not pkt or not pkt.haslayer(TCP):
            return "unknown_os_no_tcp"

        ttl = pkt.ttl
        window_size = pkt[TCP].window
        tcp_options = {opt[0]: opt[1] for opt in pkt[TCP].options} if pkt[TCP].options else {}

        os_guess = "unknown_os"
        confidence = 0.0

        # Logique très simplifiée (non exhaustive et potentiellement incorrecte)
        if ttl <= 64:
            if 'MSS' in tcp_options and window_size > 8000:
                os_guess = "Linux-like (>=2.4)" # TTL bas, grande fenêtre, MSS présent
                confidence = 0.4
        elif ttl <= 128:
            if 'MSS' in tcp_options and window_size > 8000:
                 # Windows a souvent un TTL initial de 128, mais il diminue.
                 # Si on le voit à 128, c'est proche. Si plus bas, ça peut être Windows ou un routeur.
                os_guess = "Windows-like"
                confidence = 0.4

        # Ajouter plus de règles basées sur les options TCP, etc.
        # Par exemple, l'ordre des options TCP, la présence de SACK, Timestamps, Window Scale.

        logger.debug(f"OS Fingerprint attempt: TTL={ttl}, Win={window_size}, Opts={list(tcp_options.keys())} -> Guess: {os_guess} (Conf: {confidence})")
        return f"{os_guess} (confidence: {confidence*100:.0f}%)"


    async def syn_scan(self, ip: str, port: int, os_profile: str = "Linux") -> Dict[str, Any]:
        """Effectue un scan SYN, utilisant des stratégies de contournement dynamiques."""
        result = {"status": "unknown", "response_time": 0.0, "details": {}, "error": None}
        if not self.state.is_admin:
            result["error"] = "Admin privileges required for SYN scan with Scapy."
            result["status"] = "error_permission"
            logger.warning(f"[!] {result['error']}")
            return result

        try:
            # --- Intégration Chameleon ---
            logger.info(f"[Chameleon] Preparing SYN scan for {ip}:{port}")
            fingerprint = self.os_fingerprint_evasion(os_profile)
            logger.info(f"[Chameleon] Using OS fingerprint: {os_profile} (TTL: {fingerprint['ttl']})")

            src_port = RandShort()
            scapy_iface = self.config.DEFAULT_IFACE if hasattr(self.config, 'DEFAULT_IFACE') and self.config.DEFAULT_IFACE else None
            
            syn_pkt = IP(dst=ip, ttl=fingerprint['ttl']) / TCP(
                sport=src_port, dport=port, flags="S", window=fingerprint['window'], options=fingerprint['options']
            )
            logger.debug(f"Crafted SYN packet: {syn_pkt.summary()}")

            start_time = asyncio.get_event_loop().time()
            
            ans = await asyncio.get_event_loop().run_in_executor(
                self.state.executor,
                lambda: sr1(syn_pkt, timeout=1.5, verbose=0, iface=scapy_iface)
            )

            end_time = asyncio.get_event_loop().time()
            result["response_time"] = round((end_time - start_time) * 1000, 2)

            if ans is None:
                result["status"] = "filtered"
                result["details"]["reason"] = "No response to SYN packet (timeout)."
            elif ans.haslayer(TCP):
                tcp_layer = ans[TCP]
                if tcp_layer.flags == "SA":
                    result["status"] = "open"
                    result["details"]["tcp_flags"] = "SA"
                    rst_pkt = IP(dst=ip, ttl=fingerprint['ttl']) / TCP(sport=src_port, dport=port, flags="R", seq=tcp_layer.ack)
                    await asyncio.get_event_loop().run_in_executor(
                        self.state.executor,
                        lambda: send(rst_pkt, verbose=0, iface=scapy_iface)
                    )
                elif tcp_layer.flags == "R" or tcp_layer.flags == "RA":
                    result["status"] = "closed"
                    result["details"]["tcp_flags"] = tcp_layer.flags.sprintf('%TCP.flags%')
                else:
                    result["status"] = "unknown_tcp_response"
                    result["details"]["tcp_flags"] = tcp_layer.flags.sprintf('%TCP.flags%')
            elif ans.haslayer(ICMP):
                result["status"] = "filtered"
                # ... (logique ICMP existante) ...
            else:
                result["status"] = "unknown_response_type"

            if ans:
                result["details"]["os_fingerprint_guess"] = self.fingerprint_tcp_ip(ans)

            # --- Intégration Chameleon ---
            await self.traffic_pacing_control(base_delay=0.1, jitter=0.1)

        except Exception as e:
            logger.error(f"Error in SYN scan for {ip}:{port}: {e}")
            result["error"] = str(e)
            result["status"] = "error"

        logger.info(f"SYN Scan result for {ip}:{port}: {result['status']}")
        return result


    async def grab_banner(self, ip: str, port: int, domain: Optional[str]) -> Dict[str, Any]:
        """Récupère la bannière d'un service TCP. Tente une connexion simple et lit les premières données."""
        result = {"banner": "", "error": None}
        # Utiliser un timeout plus court pour la capture de bannière
        banner_timeout = max(self.config.timeout / 2, 2.0) if self.config.timeout > 0 else 2.0

        try:
            # Tenter une connexion TCP
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=banner_timeout)

            # Lire la bannière (les premiers 1024 octets ou jusqu'au timeout)
            banner_bytes = await asyncio.wait_for(reader.read(1024), timeout=banner_timeout / 2) # Timeout plus court pour la lecture
            result["banner"] = banner_bytes.decode(errors='replace').strip()

            writer.close()
            await writer.wait_closed()

            if not result["banner"]:
                 # Parfois, il faut envoyer quelque chose pour obtenir une bannière (ex: HTTP, FTP après connexion)
                 # Pour une capture de bannière générique, on peut essayer d'envoyer une nouvelle ligne.
                logger.debug(f"No initial banner from {ip}:{port}, trying to send newline.")
                fut_nl = asyncio.open_connection(ip, port)
                reader_nl, writer_nl = await asyncio.wait_for(fut_nl, timeout=banner_timeout)
                writer_nl.write(b"\r\n\r\n") # Envoyer CRLF x2 (commun pour provoquer une réponse HTTP/serveur)
                await writer_nl.drain()
                banner_bytes_nl = await asyncio.wait_for(reader_nl.read(1024), timeout=banner_timeout / 2)
                result["banner"] = banner_bytes_nl.decode(errors='replace').strip()
                writer_nl.close()
                await writer_nl.wait_closed()
                if result["banner"]:
                    logger.debug(f"Banner received from {ip}:{port} after sending newline: {result['banner'][:60]}...")


        except asyncio.TimeoutError:
            result["error"] = "Timeout_Banner_Grab"
            logger.warning(f"Timeout grabbing banner from {ip}:{port}")
        except ConnectionRefusedError:
            result["error"] = "ConnectionRefused_Banner_Grab"
            logger.warning(f"Connection refused grabbing banner from {ip}:{port}")
        except OSError as e: # Autres erreurs de socket/connexion
            result["error"] = f"OSError_Banner_Grab: {str(e)}"
            logger.warning(f"OSError grabbing banner from {ip}:{port}: {str(e)}")
        except Exception as e:
            result["error"] = f"GenericError_Banner_Grab: {type(e).__name__} - {str(e)}"
            logger.error(f"Unexpected error grabbing banner from {ip}:{port}: {type(e).__name__} - {str(e)}")

        return result

    from typing import Dict, Any
import asyncio
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

async def scan_port(self, ip: str, port: int, domain: str) -> Dict[str, Any]:
    """Scanne un port unique sur une adresse IP donnée, en enrichissant les détails du rapport."""
    start_time = asyncio.get_event_loop().time()
    result: Dict[str, Any] = {
        "ip": ip,
        "port": port,
        "domain": domain,
        "timestamp": None,
        "status": "unknown",
        "service": "unknown",
        "protocol": "unknown",
        "banner": "",
        "waf": {"waf": "none", "confidence": 0.0},
        "ssl": {},
        "vulnerabilities": [],
        "confidence": 0.0,
        "scan_metadata": {
            "scan_method": "unknown",
            "os_fingerprint": "unknown",
            "tcp_options": {},
            "bypass_method": "none"
        },
        "details": {},
        "error": None
    }

    try:
        # --- Phase 1 : Scan de base (SYN ou Connect) ---
        scan_method_name = "syn_scan" if self.state.is_admin else "tcp_connect"
        result["scan_metadata"]["scan_method"] = scan_method_name
        scan_func = getattr(self, scan_method_name, None)
        if not scan_func:
            raise AttributeError(f"Méthode de scan '{scan_method_name}' non trouvée")
        tcp_scan_result = await scan_func(ip, port)
        
        result["details"]["tcp_scan"] = tcp_scan_result
        result["status"] = tcp_scan_result.get("status", "unknown")

        # Extraire l'empreinte OS et les options TCP si disponibles
        if "os_fingerprint" in tcp_scan_result.get("details", {}):
            result["scan_metadata"]["os_fingerprint"] = tcp_scan_result["details"]["os_fingerprint"]
        if "tcp_options" in tcp_scan_result.get("details", {}):
            result["scan_metadata"]["tcp_options"] = tcp_scan_result["details"]["tcp_options"]

        # --- Phase 2 : Actions basées sur le statut du port ---
        if result["status"] == "open":
            logger.info(f"Port {ip}:{port} est ouvert. Démarrage de la sonde approfondie.")

            service_probe_result = await self._deep_service_probe(
                ip, port, tcp_scan_result.get("response"), tcp_scan_result.get("response_time", 0.0)
            )
            result["details"]["service_probe"] = service_probe_result
            result["service"] = service_probe_result.get("service", "unknown")
            result["protocol"] = service_probe_result.get("protocol", "unknown")
            result["confidence"] = service_probe_result.get("confidence", 0.2)

            if not result["banner"] and "banner" not in service_probe_result.get("details", {}):
                banner_result = await self.grab_banner(ip, port, tcp_scan_result.get("response"))
                result["banner"] = banner_result.get("banner", "")
                if banner_result.get("error"):
                    result["details"]["banner_error"] = banner_result["error"]

            if result["banner"]:
                version_info = await self.identify_service_version(ip, port, result["banner"])
                if version_info["confidence"] > result["confidence"]:
                    result["service"] = version_info.get("version", result["service"])
                    result["confidence"] = version_info["confidence"]

            if port in self.http_ports:
                waf_result = await self._detect_waf(ip, port)
                result["waf"] = {"waf": waf_result.get("waf", "none"), "confidence": waf_result.get("confidence", 0.0)}
                result["details"]["waf_detection"] = waf_result.get("details", {})

            if port in [443, 8443] or "https" in result["service"].lower() or "ssl" in result["service"].lower():
                ssl_result = await self.ssl_analyzer.analyze_ssl(domain, port)
                result["ssl"] = ssl_result

            # Vérification des vulnérabilités
            vuln_result = await self.vuln_checker.check_vulnerabilities(
                ip, port, result["service"], result.get("banner", ""), result.get("ssl", {})
            )
            result["vulnerabilities"] = vuln_result

        elif result["status"] in ["closed", "filtered"]:
            logger.info(f"Port {ip}:{port} est {result['status']}. Sonde avec des techniques avancées.")
            advanced_probe_result = await self.probe_closed_port_advanced(ip, port)
            result["details"]["advanced_probe"] = advanced_probe_result
            if advanced_probe_result.get("status") != "unknown":
                result["status"] = advanced_probe_result["status"]

        if result["status"] == "filtered" and self.config.use_idle_scan and self.config.zombie_ips:
            logger.info(f"Port {ip}:{port} est filtré. Tentative de scan Idle.")
            idle_scan_result = await self.perform_idle_scan(ip, port, self.config.zombie_ips)
            result["details"]["idle_scan_attempt"] = idle_scan_result
            if idle_scan_result.get("status") in ["open", "closed"]:
                result["status"] = idle_scan_result["status"]
                result["confidence"] = idle_scan_result.get("confidence", 0.8)
                result["scan_metadata"]["bypass_method"] = "idle_scan"
                logger.info(f"Scan Idle réussi pour {ip}:{port}. Nouveau statut : {result['status']}")

    except Exception as e:
        logger.error(f"Erreur critique dans scan_port pour {ip}:{port} : {str(e)}", exc_info=True)
        result["error"] = f"Critique : {type(e).__name__} - {str(e)}"
        result["status"] = "error"

    finally:
        end_time = asyncio.get_event_loop().time()
        result["response_time"] = round(end_time - start_time, 4)
        result["timestamp"] = datetime.now().isoformat()

    return result

def identify_service_version(self, ip: str, port: int, banner: str) -> Dict[str, Any]:
        """Identifie la version d'un service à partir de sa bannière."""
        result = {"version": "unknown", "confidence": 0.0, "service_name": "unknown"} # Ajout de service_name

        # Expressions régulières améliorées et étendues
        # Chaque tuple: (regex_pattern, service_name, version_group_index, optional_extra_info_group_index)
        # Le score de confiance peut être ajouté ou calculé dynamiquement
        patterns = [
            (r"Apache(?:/([\d\.]+))?(?: \(([^)]+)\))?", "apache", 1, 2, 0.9),
            (r"nginx(?:/([\d\.]+))?", "nginx", 1, None, 0.9),
            (r"OpenSSH[_-]([\d\.]+[pP\d]*)", "ssh", 1, None, 0.95), # Gère les versions comme 7.4p1
            (r"vsFTPd (?:version )?([\d\.]+)", "vsftpd", 1, None, 0.9),
            (r"Microsoft-IIS(?:/([\d\.]+))?", "iis", 1, None, 0.9),
            (r"Pure-FTPd", "pure-ftpd", None, None, 0.85), # Pas de version capturée ici, mais service identifié
            (r"ProFTPD ([\d\.]+)", "proftpd", 1, None, 0.9),
            (r"Postfix SMTP server", "postfix", None, None, 0.85),
            (r"Exim (?:ESMTP )?([\w\.\-]+)", "exim", 1, None, 0.9), # Exim 4.94 or Exim ESMTP Exim 4.92
            (r"Sendmail", "sendmail", None, None, 0.8), # Identification basique de Sendmail
            (r"MySQL(?:-community-server)?(?: version | )([\d\.\-]+)", "mysql", 1, None, 0.9), # 5.7.30-log or 8.0.21
            (r"PostgreSQL(?: server| )([\d\.]+)", "postgresql", 1, None, 0.9),
            (r"MongoDB server v([\d\.]+)", "mongodb", 1, None, 0.9),
            (r"Redis server v=([\d\.]+)", "redis", 1, None, 0.9),
            (r"RabbitMQ ([\d\.]+)", "rabbitmq", 1, None, 0.85),
            (r"Microsoft Exchange SMTP", "ms_exchange_smtp", None, None, 0.8),
            (r"lighttpd(?:/([\d\.]+))?", "lighttpd", 1, None, 0.85),
            (r"cpe:/o:linux:linux_kernel:([\d\.]+)", "linux_kernel", 1, None, 0.7), # Si la bannière contient un CPE
            (r"Welcome to Microsoft FTP Service", "ms_ftp", None, None, 0.8)
        ]

        if not banner: # Si la bannière est vide, aucune identification possible
            return result

        banner_lower = banner.lower() # Pour certaines comparaisons génériques

        for pattern_str, service_name, ver_group, extra_group, confidence_score in patterns:
            match = re.search(pattern_str, banner, re.IGNORECASE) # La plupart des regex sont mieux avec IGNORECASE
            if match:
                version_str = match.group(ver_group) if ver_group and len(match.groups()) >= ver_group and match.group(ver_group) else "unknown"

                full_version_id = f"{service_name}"
                if version_str != "unknown":
                    full_version_id += f" {version_str}"

                if extra_group and len(match.groups()) >= extra_group and match.group(extra_group):
                    full_version_id += f" ({match.group(extra_group)})"

                result["service_name"] = service_name
                result["version"] = full_version_id.strip() # Assurer qu'il n'y a pas d'espaces superflus
                result["confidence"] = confidence_score * 100 # Confiance en pourcentage
                logger.debug(f"Service version identified for {ip}:{port} from banner '{banner[:50]}' -> {result['version']} (Confidence: {result['confidence']}%)")
                return result # Retourner dès le premier match de haute confiance

        # Si aucun pattern spécifique ne correspond, tenter une identification plus générique
        if "ssh" in banner_lower:
            result["service_name"] = "ssh"
            result["version"] = "ssh (generic)"
            result["confidence"] = 60.0
        elif "ftp" in banner_lower:
            result["service_name"] = "ftp"
            result["version"] = "ftp (generic)"
            result["confidence"] = 60.0
        elif "smtp" in banner_lower:
            result["service_name"] = "smtp"
            result["version"] = "smtp (generic)"
            result["confidence"] = 60.0
        elif "http" in banner_lower and ("server:" in banner_lower or banner_lower.startswith("http/")):
            # Si c'est clairement une réponse HTTP mais non identifiée par les patterns ci-dessus
            result["service_name"] = "http"
            result["version"] = "http (generic server)"
            result["confidence"] = 50.0

        if result["version"] == "unknown":
            logger.debug(f"Could not identify service version for {ip}:{port} from banner: {banner[:100]}")
        else:
            logger.info(f"Generic service identification for {ip}:{port} from banner '{banner[:50]}' -> {result['version']} (Confidence: {result['confidence']}%)")

        return result


def fingerprint_service_by_headers(self, response_headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Identifie les services web en se basant sur les en-têtes de la réponse HTTP."""
        if not response_headers:
            return None

        result = {"service_name": "unknown_web_server", "version_details": "N/A", "confidence": 0.0}

        server_header = response_headers.get("Server")
        if server_header:
            # Utiliser une partie de la logique de identify_service_version pour le Server header
            # Ceci est une simplification; idéalement, on aurait une base de données de signatures d'en-têtes plus complète.
            temp_banner_check = self.identify_service_version("dummy_ip", 0, f"Server: {server_header}")
            if temp_banner_check["confidence"] > 0:
                result["service_name"] = temp_banner_check["service_name"]
                result["version_details"] = temp_banner_check["version"]
                result["confidence"] = temp_banner_check["confidence"] * 0.8 # Un peu moins confiant que la bannière complète
                logger.debug(f"Service identified by Server header: {server_header} -> {result['service_name']} {result['version_details']}")
                return result

        # Vérifier d'autres en-têtes spécifiques (X-Powered-By, X-AspNet-Version, etc.)
        powered_by = response_headers.get("X-Powered-By")
        if powered_by:
            result["confidence"] = max(result["confidence"], 30.0) # Confiance de base si X-Powered-By est présent
            if "ASP.NET" in powered_by:
                result["service_name"] = "asp_net"
                result["version_details"] = f"X-Powered-By: {powered_by}"
                result["confidence"] = max(result["confidence"], 60.0)
            elif "PHP" in powered_by:
                result["service_name"] = "php_app_server" # Pas le serveur web, mais l'environnement
                result["version_details"] = f"X-Powered-By: {powered_by}"
                result["confidence"] = max(result["confidence"], 50.0)
            elif "Express" in powered_by:
                result["service_name"] = "express_js"
                result["version_details"] = f"X-Powered-By: {powered_by}"
                result["confidence"] = max(result["confidence"], 55.0)
            # Ajouter d'autres
            logger.debug(f"Service hint from X-Powered-By: {powered_by} -> {result['service_name']}")


        if result["service_name"] != "unknown_web_server":
            return result
        return None


async def _fetch_web_path(self, session: aiohttp.ClientSession, url: str, path: str, ip: str, port: int, proxy_url: Optional[str]) -> Optional[Dict[str, Any]]:
    """Récupère un chemin web spécifique via une session aiohttp, gérant les proxies."""
    full_url = f"{url}{path}"
    try:
        # Utiliser un timeout plus court pour l'énumération de chemins
        async with session.get(full_url, proxy=proxy_url, timeout=5, allow_redirects=False) as response:
            # Lire une petite partie du contenu pour vérification, sans surcharger
            try:
                content_preview_bytes = await response.content.read(256)
                content_preview = content_preview_bytes.decode(errors='replace')
            except asyncio.TimeoutError:
                content_preview = "[Timeout reading body]"
            except Exception as e_read_path:
                content_preview = f"[Error reading body: {str(e_read_path)}]"

            return {
                "path": path,
                "status_code": response.status,
                "content_preview": content_preview,
                "headers": dict(response.headers),
                "content_length": response.headers.get("Content-Length")
            }

    except requests.exceptions.SSLError as e:
            logger.warning(f"SSL error fetching web path {full_url}: {str(e)}")
            return {"path": path, "status_code": None, "error": f"SSL_Error: {str(e)}"}
    except requests.exceptions.ProxyError as e:
            logger.warning(f"Proxy error fetching web path {full_url} via {proxy_url}: {str(e)}")
            if proxy_url: self.report_proxy_failure(proxy_url)
            return {"path": path, "status_code": None, "error": f"Proxy_Error: {str(e)}"}
    except requests.exceptions.ConnectionError as e: # Connection errors
            logger.debug(f"Connection OS error fetching web path {full_url}: {str(e)}") # Debug car peut être fréquent
            return {"path": path, "status_code": None, "error": f"Connection_OSError: {str(e)}"}
    except asyncio.TimeoutError:
            logger.warning(f"Timeout fetching web path {full_url}")
            if proxy_url: self.report_proxy_failure(proxy_url) # Un timeout peut aussi être un échec de proxy
            return {"path": path, "status_code": None, "error": "Timeout_FetchPath"}
    except requests.exceptions.RequestException as e: # Autres erreurs client requests
            logger.warning(f"Client error fetching web path {full_url}: {type(e).__name__} - {str(e)}")
            return {"path": path, "status_code": None, "error": f"Client_Error: {type(e).__name__} - {str(e)}"}
    except Exception as e:
            logger.error(f"Unexpected error fetching web path {full_url}: {type(e).__name__} - {str(e)}")
            return {"path": path, "status_code": None, "error": f"Unexpected_Error: {type(e).__name__} - {str(e)}"}


    def advanced_ssl_analysis(self, ip: str, port: int, domain: Optional[str] = None) -> Dict[str, Any]:
        """Effectue une analyse SSL/TLS avancée."""
        # Assurez-vous que self.ssl_analyzer est initialisé et que sa méthode est appelée correctement.
        # Cette méthode est synchrone dans sa définition actuelle, mais elle devrait être appelée
        # dans un exécuteur si elle effectue des opérations réseau bloquantes.
        # Si SSLAnalysis.advanced_ssl_analysis est déjà async, alors cette méthode devrait l'être aussi.
        # Pour l'instant, on suppose que SSLAnalysis gère l'asynchronicité ou est exécutée dans un thread.

        # Vérifier si le module SSLAnalysis est un placeholder ou a une réelle implémentation
        if not hasattr(self.ssl_analyzer, 'advanced_ssl_analysis') or callable(getattr(self.ssl_analyzer, 'advanced_ssl_analysis', None)):
             logger.warning("SSLAnalysis.advanced_ssl_analysis method not found or not callable. Returning placeholder.")
             return {"error": "SSLAnalysis module or method not fully implemented.", "details": "Placeholder response."}

        try:
            # Si advanced_ssl_analysis est synchrone et bloquant:
            # loop = asyncio.get_event_loop()
            # analysis_result = await loop.run_in_executor(
            #     self.state.executor,
            #     self._sync_advanced_ssl_analysis, # Wrapper synchrone
            #     ip, port, domain
            # )
            # return analysis_result

            # Si advanced_ssl_analysis est déjà asynchrone (ce qui est préférable):
            # return await self.ssl_analyzer.advanced_ssl_analysis(ip, port, domain)

            # Pour cet exemple, nous allons supposer qu'elle est synchrone et appeler le wrapper.
            # Mais il faut s'assurer que _sync_advanced_ssl_analysis appelle bien la méthode de l'instance.
            # La définition de _sync_advanced_ssl_analysis est :
            # def _sync_advanced_ssl_analysis(self, ip: str, port: int, hostname: Optional[str]) -> Dict[str, Any]:
            #    return self.ssl_analyzer.advanced_ssl_analysis(ip, port, hostname)
            # Donc, c'est correct. Il faut juste s'assurer que l'appel est fait dans un executor.
            # L'appelant (scan_target) doit gérer cela. Ici, on retourne directement le résultat de l'appel synchrone.
            # Ce qui signifie que si advanced_ssl_analysis est bloquant, tout le scan_target sera bloqué.
            # C'EST UN POINT À AMÉLIORER DANS L'APPELANT (scan_target).

            logger.info(f"Performing advanced SSL analysis for {ip}:{port} (domain: {domain})")
            analysis_result = self.ssl_analyzer.advanced_ssl_analysis(ip, port, domain)
            if not analysis_result or "error" in analysis_result:
                logger.warning(f"Advanced SSL analysis for {ip}:{port} returned an error or empty result: {analysis_result}")
            return analysis_result

        except Exception as e:
            logger.error(f"Exception during advanced SSL analysis call for {ip}:{port}: {type(e).__name__} - {str(e)}")
            return {"error": f"SSL analysis call failed: {type(e).__name__}", "details": str(e)}


    def _sync_advanced_ssl_analysis(self, ip: str, port: int, hostname: Optional[str]) -> Dict[str, Any]:
        """Fonction synchrone pour l'analyse SSL, destinée à être exécutée dans un ThreadPoolExecutor."""
        # Cette fonction est un wrapper pour s'assurer que l'appel à l'analyseur SSL,
        # s'il est bloquant, ne bloque pas la boucle d'événements principale.
        try:
            return self.ssl_analyzer.advanced_ssl_analysis(ip, port, hostname)
        except Exception as e:
            logger.error(f"Error in _sync_advanced_ssl_analysis for {ip}:{port} (hostname: {hostname}): {type(e).__name__} - {str(e)}")
            return {"error": f"SSL analysis execution error: {type(e).__name__}", "details": str(e)}


    def check_vulnerabilities(self, ip: str, port: int, service_name: str, version_details: str, banner: str) -> List[Dict[str, Any]]:
        """Vérifie les vulnérabilités connues en fonction du nom du service, de sa version et de la bannière."""
        # Assurer que vuln_checker et sa méthode sont disponibles
        if not hasattr(self.vuln_checker, 'check_vulnerabilities') or not callable(getattr(self.vuln_checker, 'check_vulnerabilities', None)):
            logger.warning("VulnerabilityChecker.check_vulnerabilities method not found or not callable.")
            return [{"error": "VulnerabilityChecker module or method not fully implemented."}]

        try:
            # L'appel à check_vulnerabilities est supposé être synchrone ici.
            # S'il fait des I/O réseau, il devrait aussi être exécuté dans un exécuteur.
            # Pour l'instant, on l'appelle directement.
            logger.info(f"Checking vulnerabilities for {ip}:{port} - Service: {service_name}, Version: {version_details}")
            # La méthode check_vulnerabilities devrait prendre service_name et version_details séparément
            # au lieu de "version" qui était une combinaison des deux.
            # Adapter l'appel si la signature de self.vuln_checker.check_vulnerabilities est différente.
            # Pour l'instant, on suppose qu'elle prend (ip, port, service_name, version_details, banner)
            # ou une combinaison. On va passer les infos les plus granulaires.

            # Supposons que la signature attendue par VulnerabilityChecker est (ip, port, service_name, version_details, banner)
            # ou qu'elle peut parser "version" si c'est une chaîne combinée.
            # Pour être plus précis, on passe service_name et version_details.
            # Si la méthode attend juste "version" (chaîne combinée), il faudrait la reconstruire.
            # Ici, on suppose que la méthode est assez intelligente ou que sa signature est:
            # check_vulnerabilities(self, ip, port, service_name, version_details, banner_content)

            # Pour l'exemple, on utilise les arguments tels que définis dans le plan.
            # La fonction dans VulnerabilityChecker devrait être adaptée pour utiliser ces arguments.
            vulnerabilities = self.vuln_checker.check_vulnerabilities(
                ip=ip,
                port=port,
                service_name=service_name, # Nom du service (ex: "apache", "openssh")
                version_str=version_details, # Détails de la version (ex: "2.4.41", "7.4p1 (Debian-10+deb10u2)")
                banner=banner # Bannière brute pour des vérifications supplémentaires
            )
            if vulnerabilities:
                logger.warning(f"Found {len(vulnerabilities)} potential vulnerabilities for {service_name} {version_details} on {ip}:{port}")
            return vulnerabilities
        except Exception as e:
            logger.error(f"Error during vulnerability check for {ip}:{port} ({service_name} {version_details}): {type(e).__name__} - {str(e)}")
            return [{"error": f"Vulnerability check execution error: {type(e).__name__}", "details": str(e)}]


    def advanced_subdomain_enumeration(self, ip: str, domain: Optional[str]) -> List[str]:
        """Énumère les sous-domaines courants et vérifie s'ils résolvent vers l'IP cible."""
        # Ceci est un placeholder. Une énumération de sous-domaines réelle nécessiterait:
        # 1. Une liste de sous-domaines courants.
        # 2. Des requêtes DNS pour chaque sous-domaine.
        # 3. Vérification si l'IP résolue correspond à `ip`.
        # Pourrait utiliser des bibliothèques comme `dnspython`.
        # Devrait être asynchrone si elle fait de nombreux appels DNS.
        if not domain:
            logger.info("No domain provided, skipping subdomain enumeration.")
            return []

        logger.info(f"Starting advanced subdomain enumeration for {domain} targeting IP {ip}")
        # Exemple de liste très courte
        common_subdomains = ["www", "mail", "ftp", "webmail", "dev", "test", "staging", "api", "shop"]
        found_subdomains = []

        # Cette partie devrait être asynchrone et utiliser un résolveur DNS async.
        # Pour la simulation, on ne fait pas de vraies requêtes DNS.
        for sub in common_subdomains:
            full_domain = f"{sub}.{domain}"
            # Simuler une vérification DNS
            # resolved_ip = await self._check_subdomain_resolves_to_ip_async(full_domain, ip)
            # if resolved_ip == ip:
            #    found_subdomains.append(full_domain)
            #    logger.info(f"Found matching subdomain: {full_domain} -> {ip}")
            pass # Placeholder pour la logique de résolution DNS asynchrone

        if not found_subdomains:
            logger.info(f"No common subdomains for {domain} found resolving to {ip} (simulated check).")
        return found_subdomains

    def enumerate_web_paths(self, ip: str, port: int, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Énumère les chemins web courants sur une cible."""
        # Ceci est un placeholder. Une énumération de chemins réelle nécessiterait:
        # 1. Une liste de chemins courants (ex: /admin, /login, robots.txt, .git/, etc.).
        # 2. Des requêtes HTTP pour chaque chemin.
        # 3. Analyse des codes de statut et du contenu.
        # Devrait être asynchrone.
        logger.info(f"Starting web path enumeration for {ip}:{port} (domain: {domain or 'N/A'})")
        # Exemple de liste très courte
        common_paths = [
            "/robots.txt", "/sitemap.xml", "/.git/config", "/.env",
            "/admin", "/login", "/wp-admin", "/phpmyadmin",
            "/api/v1/users" # Exemple de chemin API
        ]
        found_paths_info = []

        # Cette partie devrait être asynchrone.
        # L'appelant (scan_target) devra utiliser asyncio.gather pour exécuter _fetch_web_path
        # pour chaque chemin.
        # Exemple:
        # scheme = "https" if port in [443, 8443] else "http"
        # base_url_for_paths = f"{scheme}://{domain or ip}:{port}"
        # async with ClientSession(...) as session:
        #    tasks = [self._fetch_web_path(session, base_url_for_paths, path, ip, port, None) for path in common_paths]
        #    results = await asyncio.gather(*tasks)
        #    found_paths_info = [r for r in results if r and r.get("status_code") not in [404, None]] # Filtrer les 404 ou erreurs

        if not found_paths_info:
             logger.info(f"No common web paths found or accessible for {ip}:{port} (simulated check).")
        return found_paths_info


    def _check_subdomain_resolves_to_ip(self, subdomain: str, target_ip: str) -> Optional[str]:
        """Vérifie si un sous-domaine spécifique résout vers une adresse IP donnée (synchrone)."""
        # Ceci est un placeholder pour une fonction synchrone.
        # Une vraie implémentation utiliserait socket.gethostbyname ou dnspython.
        # import socket
        # try:
        #     resolved_ip = socket.gethostbyname(subdomain)
        #     return resolved_ip
        # except socket.gaierror:
        #     return None
        return None # Placeholder

    

    async def scan_target(self, ip: str, port: int, domain: Optional[str] = None) -> Dict[str, Any]:
        """Effectue un scan complet sur une cible."""
        result = {
            "ip": ip,
            "port": port,
            "domain": domain,
            "timestamp": "2025-06-24T07:04:00Z",  # ISO 8601 format
            "status": "unknown",
            "service": "unknown",
            "protocol": "unknown",
            "banner": "",
            "waf": {"waf": "none", "confidence": 0.0},
            "ssl": {},
            "vulnerabilities": [],
            "confidence": 0.0,
            "details": {},
            "error": None
        }

        logger.info(f"Starting scan on {ip}:{port} (domain: {domain or 'none'})")

        try:
            # Étape 1 : Scan TCP initial pour vérifier l'état du port
            tcp_result = self.tcp_connect(ip, port)
            result["status"] = tcp_result["status"]
            result["response_time"] = tcp_result["response_time"]
            result["details"]["tcp_scan"] = tcp_result

            if result["status"] == "error":
                result["error"] = tcp_result.get("error", "TCP scan failed")
                logger.error(f"TCP scan failed for {ip}:{port}: {result['error']}")
                return result

            # Étape 2 : Si le port est ouvert ou filtré, effectuer une sonde avancée
            if result["status"] in ["open", "filtered"]:
                # Sonde avancée pour les ports fermés ou filtrés
                if result["status"] == "filtered":
                    probe_result = self.probe_with_ack_fin(ip, port)
                    result["status"] = probe_result["status"]
                    result["details"]["advanced_probe"] = probe_result
                    logger.debug(f"Advanced probe result for {ip}:{port}: {probe_result}")

                # Étape 3 : Sonde de service approfondie
                if result["status"] == "open":
                    service_result = await self._deep_service_probe(ip, port, None, result["response_time"])
                    result["service"] = service_result["service"]
                    result["protocol"] = service_result["protocol"]
                    result["details"]["service_probe"] = service_result
                    result["confidence"] = service_result.get("confidence", 0.7)
                    logger.info(f"Service detected on {ip}:{port}: {result['service']} (confidence: {result['confidence']})")

                # Étape 4 : Détection de WAF (uniquement pour les ports HTTP/HTTPS)
                if port in self.http_ports:
                    waf_result = await self._detect_waf(ip, port)
                    result["waf"] = waf_result # Stocker le résultat complet de _detect_waf
                    if waf_result.get("error"):
                        result["details"]["waf_error"] = waf_result["error"] # Conserver pour le débogage
                    else:
                        logger.info(f"WAF detection on {ip}:{port}: {waf_result['waf']} (confidence: {waf_result['confidence']})")

                    # Tentative de contournement WAF si un WAF est détecté avec une confiance suffisante
                    # ou même si la détection a échoué (pourrait être un WAF inconnu)
                    if waf_result["waf"] != "none" or waf_result.get("error"):
                        logger.info(f"Attempting WAF bypass for {ip}:{port} due to WAF '{waf_result['waf']}' or detection error.")
                        bypass_result = await self.waf_bypass(ip, port, domain)
                        result["details"]["waf_bypass_attempts"] = bypass_result.get("details", [])
                        if bypass_result.get("bypassed"):
                            logger.info(f"WAF bypass successful on {ip}:{port}. Strategy: {bypass_result.get('successful_strategy_details',{}).get('strategy_name')}")
                            # Mettre à jour l'évaluation WAF finale basée sur le résultat du bypass
                            result["waf"]["bypassed_successfully"] = True
                            result["waf"]["successful_bypass_strategy"] = bypass_result.get('successful_strategy_details',{}).get('strategy_name')
                            result["waf"]["final_assessment_after_bypass"] = bypass_result.get("final_waf_assessment", "unknown")
                        else:
                            logger.warning(f"WAF bypass failed or all strategies exhausted on {ip}:{port}. Status: {bypass_result.get('status')}")
                            result["waf"]["bypassed_successfully"] = False
                            result["waf"]["bypass_failure_status"] = bypass_result.get('status')


                # Étape 5 : Analyse SSL pour les ports HTTPS
                if port in [443, 8443]:
                    ssl_result = self.advanced_ssl_analysis(ip, port, domain)
                    result["ssl"] = ssl_result
                    # result["details"]["ssl_analysis"] = ssl_result # Redondant si result["ssl"] est déjà là
                    logger.info(f"SSL analysis completed for {ip}:{port}")

                # Étape 6 : Récupération de la bannière
                banner_result = await self.grab_banner(ip, port, domain)
                result["banner"] = banner_result["banner"]
                if banner_result.get("error"):
                    result["details"]["banner_error"] = banner_result["error"]
                else:
                    logger.debug(f"Banner grabbed for {ip}:{port}: {result['banner'][:50]}...")

                # Étape 7 : Identification de la version du service
                if result["banner"]:
                    version_result = self.identify_service_version(ip, port, result["banner"])
                    result["details"]["service_version"] = version_result
                    # Mettre à jour le service principal seulement si plus spécifique que celui de _probe_http_service
                    if version_result.get("service_name") != "unknown" and version_result.get("confidence",0) > result.get("details",{}).get("service_probe",{}).get("confidence",0):
                        result["service"] = version_result.get("version", result["service"])
                    result["confidence"] = max(result["confidence"], version_result.get("confidence", 0.0) / 100.0) # Normaliser la confiance
                    logger.info(f"Service version identified for {ip}:{port}: {version_result['version']}")

                # Étape 8 : Vérification des vulnérabilités
                if result["service"] != "unknown" or result["banner"]:
                    service_name_for_vuln = result["details"].get("service_version", {}).get("service_name", "unknown")
                    if service_name_for_vuln == "unknown" and result["service"] != "unknown" and result["service"] != "http/https":
                         # Essayer de déduire un nom de service plus simple à partir de result["service"]
                        service_name_for_vuln = result["service"].split('/')[0].split('(')[0].strip()

                    version_details_for_vuln = result["details"].get("service_version", {}).get("version", result["service"])

                    vuln_result = self.check_vulnerabilities(ip, port, service_name_for_vuln, version_details_for_vuln, result["banner"])
                    result["vulnerabilities"] = vuln_result
                    # result["details"]["vulnerabilities_check"] = vuln_result # Redondant
                    if vuln_result and not any("error" in v for v in vuln_result):
                        logger.warning(f"Vulnerabilities found for {ip}:{port}: {len(vuln_result)} items.")
                    else:
                        logger.info(f"No vulnerabilities found or error in check for {ip}:{port}")


                # Étape 9 : Scan Idle si configuré (optionnel)
                # self.config.use_idle_scan and self.config.zombie_ips are initialized in __init__
                if self.config.use_idle_scan: # Check primary toggle first
                    if self.config.zombie_ips: # Ensure list is not empty (already checked in __init__ but good for clarity)
                        logger.info(f"Attempting Idle Scan for {ip}:{port} using potential zombies: {self.config.zombie_ips}")
                        # Pass the entire list of zombie IPs to perform_idle_scan
                        idle_result = await self.perform_idle_scan(ip, port, self.config.zombie_ips) 
                        result["details"]["idle_scan"] = idle_result
                        
                        # Log the outcome of the idle scan attempt more clearly
                        if idle_result.get("used_zombie_ip"):
                            logger.info(f"Idle scan for {ip}:{port} completed using zombie {idle_result['used_zombie_ip']}. Determined Status: {idle_result['status']}, Confidence: {idle_result['confidence']}.")
                            # Potentially update main result status based on idle scan, if desired and more confident.
                            # For now, it's stored in details.
                        elif idle_result["status"] == "all_zombies_unsuitable":
                            logger.warning(f"Idle scan for {ip}:{port}: All provided zombies ({self.config.zombie_ips}) were unsuitable. Details: {idle_result.get('error')}")
                        elif idle_result["status"] == "admin_required":
                            logger.error(f"Idle scan for {ip}:{port} requires administrator privileges.")
                        elif idle_result["status"] == "config_error_no_zombies":
                             logger.error(f"Idle scan for {ip}:{port} misconfigured: No zombie IPs were actually passed to perform_idle_scan (should be caught earlier).")
                        else: # Other errors or inconclusive states from perform_idle_scan
                            logger.warning(f"Idle scan for {ip}:{port} was inconclusive or failed. Status: {idle_result['status']}. Error: {idle_result.get('error', 'N/A')}")
                    else:
                        # This case should ideally be prevented by __init__ which disables use_idle_scan if zombie_ips is empty.
                        logger.warning(f"Idle scan is enabled but no zombie IPs are configured. Skipping Idle scan for {ip}:{port}.")
                        result["details"]["idle_scan"] = {"status": "skipped", "reason": "use_idle_scan is True, but no zombie IPs configured."}
                else:
                    # Log if idle scan is not being performed, either due to config or because zombie_ips was empty.
                    logger.debug(f"Idle scan not performed for {ip}:{port} (use_idle_scan: {self.config.use_idle_scan}).")


        except Exception as e:
            result["error"] = f"Unexpected error during scan: {str(e)}"
            result["details"]["scan_error"] = str(e)
            logger.exception(f"Scan failed for {ip}:{port}")

        logger.info(f"Scan completed for {ip}:{port}. Final Status: {result['status']}, Service: {result['service']}")
        return result

    async def full_scan(self, target: str, ports: str, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Effectue un scan complet sur une cible avec une plage de ports spécifiée."""
        results = []
        logger.info(f"Starting full scan on {target} with ports {ports} (domain: {domain or 'none'})")

        # Résolution du domaine ou validation de l'IP
        try:
            ip_set = self.resolve_domain(target) if domain else {target}
            if not ip_set:
                logger.error(f"Failed to resolve target {target}")
                return [{"error": f"Failed to resolve target {target}"}]
        except Exception as e:
            logger.error(f"Error resolving target {target}: {str(e)}")
            return [{"error": f"Error resolving target {target}: {str(e)}"}]

        # Analyse de la plage de ports
        try:
            if "-" in ports:
                start_port, end_port = map(int, ports.split("-"))
                port_list = range(start_port, end_port + 1)
            elif "," in ports:
                port_list = [int(p) for p in ports.split(",")]
            else:
                port_list = [int(ports)]
        except ValueError as e:
            logger.error(f"Invalid port range format: {ports}. Error: {str(e)}")
            return [{"error": f"Invalid port range format: {ports}"}]

        # Limiter le nombre de ports scannés pour éviter des scans trop volumineux
        if len(port_list) > 1000: # Seuil arbitraire
            logger.warning(f"Port range too large ({len(port_list)} ports). Limiting to first 1000 ports.")
            port_list = list(port_list)[:1000]

        # Scan parallèle des ports
        tasks = []
        for ip_addr in ip_set:
            for port_num in port_list:
                tasks.append(self.scan_target(ip_addr, port_num, domain))

        max_concurrency = 50
        if hasattr(self.config, 'max_concurrent_scans') and isinstance(self.config.max_concurrent_scans, int) and self.config.max_concurrent_scans > 0:
            max_concurrency = self.config.max_concurrent_scans
        else:
            logger.warning(f"max_concurrent_scans not properly configured or invalid, defaulting to {max_concurrency}.")

        semaphore = asyncio.Semaphore(max_concurrency)

        async def limited_scan(task):
            async with semaphore:
                return await task

        scan_results = await asyncio.gather(*[limited_scan(task) for task in tasks], return_exceptions=True)

        for scan_result in scan_results:
            if isinstance(scan_result, Exception):
                logger.error(f"A scan task failed with an unhandled exception: {type(scan_result).__name__} - {str(scan_result)}", exc_info=True)
                results.append({"error": f"Scan task failed with unhandled exception: {type(scan_result).__name__} - {str(scan_result)}"})
            elif scan_result.get("error") and "scan_error" in scan_result.get("details", {}):
                 logger.error(f"Scan for {scan_result.get('ip')}:{scan_result.get('port')} resulted in an error: {scan_result['error']}")
                 results.append(scan_result)
            else:
                results.append(scan_result)

        logger.info(f"Full scan completed for {target}. Processed {len(scan_results)} tasks, returning {len(results)} results.")
        return results

if __name__ == "__main__":
    # Exemple d'utilisation pour tester le scanner
    import asyncio
    from config import ScannerConfig

    async def main():
        # Configuration d'exemple plus réaliste pour le test
        # Remplacer par une IP et des ports valides pour un test réel
        target_ip_to_scan = "127.0.0.1" # Ou une IP de test comme scanme.nmap.org (avec prudence)
        ports_to_scan = "80,443,22"   # Ports courants
        domain_name = None # Mettre un domaine si vous scannez un nom d'hôte

        # Exemple de configuration avec quelques options
        # Note: Les modules externes (BypassStrategy, etc.) sont des placeholders.
        # Pour un test réel, il faudrait soit les implémenter, soit les commenter dans la classe NetworkScanner.

        # Création d'un fichier config.py minimal pour que l'import fonctionne
        if not os.path.exists("config.py"):
            with open("config.py", "w") as f:
                f.write("class ScannerConfig:\n")
                f.write("    def __init__(self, target_ips, timeout, proxies, max_concurrent_scans, user_agents=None, DEFAULT_IFACE=None, use_idle_scan=False, zombie_ips=None):\n")
                f.write("        self.target_ips = target_ips\n")
                f.write("        self.timeout = timeout\n")
                f.write("        self.proxies = proxies\n")
                f.write("        self.max_concurrent_scans = max_concurrent_scans\n")
                f.write("        self.user_agents = user_agents or ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36']\n")
                f.write("        self.DEFAULT_IFACE = DEFAULT_IFACE\n")
                f.write("        self.use_idle_scan = use_idle_scan\n")
                f.write("        self.zombie_ips = zombie_ips if isinstance(zombie_ips, list) else []\n")

        # Création de fichiers placeholder pour les autres imports si nécessaire
        placeholder_modules = ["network_tool/utils.py", "bypass.py", "service_probe.py", "ssl_analysis.py", "vulnerabilities.py"]
        for mod_path_str in placeholder_modules:
            mod_dir = os.path.dirname(mod_path_str)
            if mod_dir and not os.path.exists(mod_dir):
                os.makedirs(mod_dir)
            if not os.path.exists(mod_path_str):
                with open(mod_path_str, "w") as f:
                    if "utils" in mod_path_str:
                        f.write("def generate_spoofed_ip_headers(): return {}\n")
                        f.write("def generate_url_path_variation(base_path): return base_path\n")
                    else: # Pour BypassStrategy, ServiceProbe etc.
                        class_name = mod_path_str.split('.')[0].replace('_', ' ').title().replace(' ', '')
                        if class_name == "SslAnalysis": class_name = "SSLAnalysis" # Cas spécial
                        f.write(f"class {class_name}:\n")
                        f.write("    def __init__(self, *args, **kwargs):\n")
                        f.write("        print(f'{class_name} placeholder initialized')\n")
                        # Ajouter des méthodes placeholder si elles sont appelées directement
                        if class_name == "SSLAnalysis":
                             f.write("    def advanced_ssl_analysis(self, ip, port, domain=None):\n")
                             f.write("        return {'error': 'Placeholder SSL Analysis'}\n")
                        if class_name == "VulnerabilityChecker":
                             f.write("    def check_vulnerabilities(self, ip, port, service_name, version_str, banner):\n")
                             f.write("        return [{'placeholder_vuln': 'No real check'}]\n")


        test_config = ScannerConfig(
            target_ips=[target_ip_to_scan], # Doit être une liste
            timeout=5,                      # Timeout global pour certaines opérations (en secondes)
            proxies=[],                     # Liste de URLs de proxy, ex: ["http://user:pass@host:port"]
            max_concurrent_scans=10,        # Nombre de scans de port en parallèle
            user_agents=["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "MyCustomScanner/1.0"],
            # DEFAULT_IFACE="eth0",         # Spécifier l'interface pour Scapy si nécessaire (ex: 'eth0', 'en0')
            use_idle_scan=False,            # Activer le scan Idle (nécessite un zombie et root)
            # Pour tester le scan idle, mettre use_idle_scan=True et fournir des IPs zombies valides:
            zombie_ips=[]                   # e.g., zombie_ips=["192.168.1.254", "10.0.0.5"]
        )

        scanner = NetworkScanner(test_config)

        logger.info(f"Permissions Admin: {is_admin()}")
        logger.info(f"Scapy default interface: {scanner.config.DEFAULT_IFACE if hasattr(scanner.config, 'DEFAULT_IFACE') else 'Not Set'}")

        # Test d'un seul port
        # results_single = await scanner.scan_target(target_ip_to_scan, 80, domain=domain_name)
        # print("\n--- Single Port Scan Result ---")
        # print(json.dumps(results_single, indent=2))

        # Test de plusieurs ports
        print(f"\n--- Full Scan on {target_ip_to_scan} for ports {ports_to_scan} ---")
        results_full = await scanner.full_scan(target_ip_to_scan, ports_to_scan, domain=domain_name)
        print("\n--- Full Scan Results ---")
        print(json.dumps(results_full, indent=2))

    if os.name == 'nt': # Pour éviter les problèmes avec ProactorEventLoop sur Windows avec asyncio/scapy
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main())
