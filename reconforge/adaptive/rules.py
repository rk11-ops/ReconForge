from __future__ import annotations
from dataclasses import dataclass
import re
from ..config import API_PATH_RE, WEB_PORTS, WEB_SERVICE_TOKENS

@dataclass(frozen=True)
class Rule:
    name: str
    priority: int
    reason: str
    action: str
    matcher: str

TECH_TAG_RULES={
    'wordpress':('wordpress',80), 'swagger':('swagger',70), 'openapi':('openapi',70), 'graphql':('graphql',75),
    'nginx':('nginx',40), 'apache':('apache',40), 'iis':('iis',40), 'tomcat':('tomcat',50),
}

BASE_RULES=(
    Rule('web-service','90','Web service discovered; enumerate HTTP surface.','web-bootstrap','service'),
    Rule('api-surface',85,'API-like endpoint discovered; enumerate its local path.','api-fuzz','endpoint'),
    Rule('technology-focus',75,'High-signal technology fingerprint discovered; run focused templates.','tech-nuclei','technology'),
    Rule('parameter-candidate',95,'Parameterized endpoint discovered; run bounded SQL injection validation when enabled.','sqlmap','parameter'),
)

def web_service_found(ports):
    return any(str(p.get('port')) in WEB_PORTS or any(tok in str(p.get('service') or '').lower() for tok in WEB_SERVICE_TOKENS) for p in ports if isinstance(p,dict))

def api_endpoint(path:str)->bool:
    return bool(re.search(API_PATH_RE,path,re.I))

def parameterized(url:str)->bool:
    from urllib.parse import urlparse
    try: return bool(urlparse(url).query)
    except Exception: return False
