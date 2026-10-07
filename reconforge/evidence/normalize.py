from __future__ import annotations

import re
from typing import Any, Iterable
from urllib.parse import urlparse


def dedupe_ordered(items: Iterable[str]) -> list[str]:
    out=[]; seen=set()
    for item in items:
        if item not in seen:
            seen.add(item); out.append(item)
    return out


def extract_technologies(text: str) -> list[str]:
    low=text.lower()
    mapping={
        "nginx":r"\bnginx\b", "apache":r"\bapache(?:/|\s|$)", "iis":r"\bmicrosoft-iis\b|\biis\b",
        "php":r"\bphp(?:[/ -]|\d)", "wordpress":r"\bwordpress\b|wp-content|wp-includes|wp-admin",
        "tomcat":r"\btomcat\b", "node.js":r"\bnode(?:\.js)?\b", "express":r"\bexpress(?:\.js)?\b",
        "django":r"\bdjango\b", "laravel":r"\blaravel\b", "jetty":r"\bjetty\b", "gunicorn":r"\bgunicorn\b",
        "openresty":r"\bopenresty\b", "swagger":r"\bswagger(?:-ui)?\b|swagger\.json", "openapi":r"\bopenapi\b|openapi\.json",
        "graphql":r"\bgraphql\b|/graphql(?:/|$)", "next.js":r"\b_next/static\b|\bnext(?:\.js)?\b", "react":r"\breact\b|react-dom",
        "vue":r"\bvue(?:\.js)?\b", "asp.net":r"\basp\.net\b|__viewstate", "java":r"\bjava\b|jsessionid",
    }
    return [name for name,p in mapping.items() if re.search(p, low)]


def extract_body_markers(body: str) -> list[str]:
    patterns=((r"wp-content|wp-includes|wp-admin","WordPress"),(r"swagger-ui|swagger\.json","Swagger"),(r"openapi\.json|openapi:","OpenAPI"),(r"/graphql","GraphQL"),(r"/_next/","Next.js"))
    return dedupe_ordered([label for pattern,label in patterns if re.search(pattern, body, re.I)])


def redact_http_headers(headers: dict[str,str]) -> dict[str,str]:
    blocked={"authorization","proxy-authorization","cookie","set-cookie","x-api-key"}
    return {k:("<redacted>" if k.lower() in blocked else v) for k,v in headers.items()}


def is_same_target_url(url: str, host: str) -> bool:
    try:
        parsed=urlparse(url)
        return parsed.hostname and parsed.hostname.lower().rstrip(".") == host.lower().rstrip(".")
    except Exception:
        return False


def extract_urls_from_lines(lines: Iterable[str]) -> list[str]:
    urls=[]
    for line in lines:
        urls.extend(re.findall(r"https?://[^\s'\"<>]+", line))
    return dedupe_ordered([u.rstrip(").,;]") for u in urls])


def infer_severity(text: str) -> str:
    low=text.lower()
    if re.search(r"critical|remote code|rce|command injection", low): return "critical"
    if re.search(r"high|sql injection|ssrf|auth bypass|arbitrary file", low): return "high"
    if re.search(r"medium|xss|cors|csrf|directory listing", low): return "medium"
    if re.search(r"low|header|cookie|clickjack|information disclosure", low): return "low"
    return "info"


def classify_issue(text: str) -> str:
    low=text.lower()
    patterns=(
        ("sql-injection",r"sql injection|sqli|injectable parameter|boolean-based|time-based blind"),
        ("xss",r"cross.?site scripting|xss"),
        ("ssrf",r"server.?side request forgery|\bssrf\b"),
        ("cors",r"cors|cross-origin resource sharing"),
        ("clickjacking",r"x-frame-options|clickjack|frame-ancestors"),
        ("missing-csp",r"content-security-policy|\bcsp\b"),
        ("cookie-flags",r"secure flag|httponly|samesite|cookie flag"),
        ("directory-listing",r"directory listing|autoindex|index of /"),
        ("verbose-errors",r"stack trace|debug mode|verbose error|exception disclosure"),
        ("tls",r"weak tls|obsolete protocol|weak cipher|certificate"),
        ("exposed-admin",r"admin panel|administrator|admin interface"),
    )
    for key,pattern in patterns:
        if re.search(pattern,low): return key
    return re.sub(r"[^a-z0-9]+","-",low).strip("-")[:90] or "generic-finding"


def extract_endpoint_from_text(text: str) -> str:
    m=re.search(r"https?://[^\s'\"<>]+", text)
    if m: return m.group(0).rstrip(".,;)]")
    m=re.search(r"(/[A-Za-z0-9_./?=&%-]{1,200})",text)
    return m.group(1) if m else ""


def normalize_endpoint(value: str) -> str:
    if not value: return "/"
    try:
        p=urlparse(value)
        return p.path or "/"
    except Exception:
        return value[:200]


def normalize_finding(source: str, item: dict[str,Any]) -> dict[str,Any] | None:
    name=str(item.get("name") or item.get("template_name") or item.get("category") or item.get("issue") or "").strip()
    if not name: return None
    endpoint=str(item.get("matched_at") or item.get("url") or item.get("path") or item.get("endpoint") or "").strip()
    if not endpoint:
        endpoint=extract_endpoint_from_text(str(item.get("info") or item.get("description") or name))
    severity=str(item.get("severity") or infer_severity(name)).lower()
    if severity not in {"critical","high","medium","low","info","unknown"}: severity=infer_severity(name)
    issue_key=classify_issue(name + " " + str(item.get("info") or item.get("description") or ""))
    endpoint_norm=normalize_endpoint(endpoint)
    fingerprint=f"{issue_key}|{endpoint_norm}"
    return {
        "issue_key":issue_key,"name":name,"severity":severity,"source":source,
        "endpoint":endpoint,"endpoint_path":endpoint_norm,"fingerprint":fingerprint,"raw":item,
    }
