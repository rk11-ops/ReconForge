from __future__ import annotations
from typing import Any
from .graph import EvidenceGraph
from .normalize import extract_technologies,is_same_target_url,normalize_finding,infer_severity
from .correlate import correlate_findings
from ..utils import target_is_public

class EvidenceEngine:
    @classmethod
    def analyze(cls,ctx,results,passive)->dict[str,Any]:
        graph=EvidenceGraph(); findings_raw=[]; endpoints=set(); technologies=set(str(x).lower() for x in passive.get("technologies",[]) if isinstance(passive,dict)); ports=[]
        target=graph.node("asset",ctx.host,"target",url=ctx.web_url)
        for result in results:
            summary=result.summary if isinstance(result.summary,dict) else {}
            source=result.tool
            for p in summary.get("ports",[]) if isinstance(summary.get("ports"),list) else []:
                if not isinstance(p,dict): continue
                ports.append(p); port=str(p.get("port") or "")
                if not port: continue
                pid=graph.node("port",f"{p.get('protocol','tcp')}:{port}",source,state=p.get("state")); graph.edge(target,pid,"exposes")
                svc=" ".join(str(p.get(k) or "") for k in ("service","product","version")).strip()
                if svc:
                    sid=graph.node("service",svc,source); graph.edge(pid,sid,"runs"); technologies.update(extract_technologies(svc))
            for tech in summary.get("technologies",[]) if isinstance(summary.get("technologies"),list) else []:
                if tech: technologies.add(str(tech).lower())
            for f in summary.get("findings",[]) if isinstance(summary.get("findings"),list) else []:
                if isinstance(f,dict):
                    item=normalize_finding(source,f)
                    if item: findings_raw.append(item)
            for o in summary.get("observations",[]) if isinstance(summary.get("observations"),list) else []:
                item=normalize_finding(source,{"name":str(o),"severity":infer_severity(str(o))})
                if item: findings_raw.append(item)
            for ep in summary.get("endpoints",[]) if isinstance(summary.get("endpoints"),list) else []:
                if ep and is_same_target_url(str(ep),ctx.host): endpoints.add(str(ep))
        for marker in passive.get("body_markers",[]) if isinstance(passive,dict) else []:
            technologies.update(extract_technologies(str(marker)))
        for ep in passive.get("discovered_links",[]) if isinstance(passive,dict) else []:
            if ep and is_same_target_url(str(ep),ctx.host): endpoints.add(str(ep))
        for resource, item in (passive.get("passive_resources",{}) if isinstance(passive,dict) else {}).items():
            if isinstance(item,dict):
                final_url=item.get("final_url")
                if final_url and is_same_target_url(str(final_url),ctx.host): endpoints.add(str(final_url))
                for ep in item.get("discovered_links",[]) if isinstance(item.get("discovered_links"),list) else []:
                    if is_same_target_url(str(ep),ctx.host): endpoints.add(str(ep))
        for tech in sorted(technologies):
            tid=graph.node("technology",tech,"evidence-engine"); graph.edge(target,tid,"identified-as")
        for ep in sorted(endpoints):
            eid=graph.node("endpoint",ep,"evidence-engine"); graph.edge(target,eid,"contains")
        findings=correlate_findings(findings_raw,target_is_public(ctx.host,ctx.web_url),sorted(endpoints))
        for f in findings:
            fid=graph.node("finding",f["fingerprint"],"correlator",name=f["name"],severity=f["severity"])
            for src in f["sources"]:
                sid=graph.node("scanner",src,"correlator"); graph.edge(sid,fid,"reports")
            for ep in f.get("endpoints",[]):
                eid=graph.node("endpoint",ep,"correlator"); graph.edge(eid,fid,"supports")
        return {"graph":graph.as_dict(),"attack_surface":{"ports":ports,"technologies":sorted(technologies),"endpoints":sorted(endpoints)},"findings":findings,"passive_probe":passive,"summary":{"node_count":len(graph.nodes),"edge_count":len(graph.as_dict()["edges"]),"finding_count":len(findings),"technology_count":len(technologies),"endpoint_count":len(endpoints)}}
