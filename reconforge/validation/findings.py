from __future__ import annotations
from ..evidence.normalize import normalize_endpoint
from .headers import fetch,validate_clickjacking,validate_missing_csp,validate_cors,validate_verbose_errors,validate_directory_listing
from .cookies import validate_cookie_flags
from .tls import validate_tls

DETERMINISTIC={'clickjacking':validate_clickjacking,'cookie-flags':validate_cookie_flags,'missing-csp':validate_missing_csp,'cors':validate_cors,'verbose-errors':validate_verbose_errors,'directory-listing':validate_directory_listing}

def validate_single(ctx,finding):
    key=finding.get('issue_key'); endpoint=finding.get('endpoints',[ctx.web_url])[0] if finding.get('endpoints') else ctx.web_url
    url=endpoint if str(endpoint).startswith(('http://','https://')) else ctx.web_url.rstrip('/') + ('/' + str(endpoint).lstrip('/') if str(endpoint).strip('/') else '')
    if key in DETERMINISTIC: return DETERMINISTIC[key](url)
    if key=='tls': return validate_tls(ctx.web_url)
    # For non-deterministic classes, rely on independent corroboration instead of pretending a safe GET proves exploitability.
    if len(finding.get('sources',[]))>=2:
        return {'status':'corroborated','reason':'Independent scanner sources agree on the same normalized issue and endpoint.','evidence':{'sources':finding.get('sources',[])}}
    return {'status':'scanner-reported','reason':'Single scanner signal without a deterministic safe validator or independent corroboration.','evidence':{'sources':finding.get('sources',[])}}

def validate_findings(ctx,analysis):
    out=[]
    for f in analysis.get('findings',[]):
        v=validate_single(ctx,f); out.append({'fingerprint':f.get('fingerprint'),'validation_status':v.get('status'),'validation_reason':v.get('reason'),'validation_evidence':v.get('evidence',{})})
    return out
