from __future__ import annotations
import hashlib
from typing import Any
from .correlate import dedupe_edges

class EvidenceGraph:
    def __init__(self):
        self.nodes:dict[str,dict[str,Any]]={}
        self.edges:list[dict[str,str]]=[]
    def node(self,node_type:str,value:str,source:str,**extra:Any)->str:
        node_id=hashlib.sha256(f"{node_type}|{value}".encode()).hexdigest()[:16]
        n=self.nodes.setdefault(node_id,{"id":node_id,"type":node_type,"value":value,"sources":[]})
        if source not in n["sources"]: n["sources"].append(source)
        n.update(extra)
        return node_id
    def edge(self,source:str,target:str,relation:str)->None:
        self.edges.append({"from":source,"to":target,"relation":relation})
    def as_dict(self)->dict[str,Any]:
        return {"nodes":list(self.nodes.values()),"edges":dedupe_edges(self.edges)}
