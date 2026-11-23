import json
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Set, Tuple
from collections import defaultdict

# ===================== Configuration =====================

MODEL_NAME = "all-MiniLM-L6-v2"
model = SentenceTransformer(MODEL_NAME)
generic_ta_counter = 0

# ===================== Raw CTI Record =====================
class RawCTIRecord:
    def __init__(self,
                 raw_id: str,
                 entity_type: str,
                 entity_name: str,
                 malware_names: List[str],
                 associated_entity_names: List[str],
                 technique_list: List[str],
                 tactic_list: List[str],
                 source: str,
                 confidence: float,
                 observed_time: str,
                 report_text: str,
                 procedure: str):
        self.raw_id = raw_id
        self.entity_type = entity_type
        self.entity_name = entity_name.strip()
        self.malware_names = set(malware_names)
        self.associated_entity_names = set(associated_entity_names)
        self.technique_list = set(technique_list)
        self.tactic_list = set(tactic_list)
        self.source = source
        self.confidence = confidence
        self.observed_time = observed_time
        self.report_text = report_text
        self.procedure = procedure
        self.procedure_emb = model.encode(procedure, normalize_embeddings=True)

# ===================== Union-Find =====================
class UnionFind:
    def __init__(self, size: int):
        self.parent = list(range(size))

    def find(self, x: int) -> int:
        if self.parent[x] != x:
            self.parent[x] = self.find(self.parent[x])
        return self.parent[x]

    def union(self, x: int, y: int):
        rx = self.find(x)
        ry = self.find(y)
        if rx != ry:
            self.parent[ry] = rx

def parse_raw_cti(raw_cti_item: Dict, default_observed_time: str = "2023-03-01") -> List[RawCTIRecord]:
    """
    Parse one raw CTI record into RawCTIRecord(s).
    One sentence may contain one threat-actor entity, which becomes one record.
    If no threat-actor entity exists, this sentence cannot be anchored to a TA cluster.
    """
    sentence_text = raw_cti_item["sentence_text"]
    source = raw_cti_item["source"]
    raw_id = raw_cti_item["uid"]
    techniques_data = raw_cti_item.get("techniques") or []
    tactics_data = raw_cti_item.get("tactic") or []
    technique_list = [tech["id"] for tech in techniques_data]
    tactic_list = [tech["id"] for tech in tactics_data]

    malware_names = []
    infra_names = []
    threat_actor_names = []
    action_names = []

    for ent in raw_cti_item.get("entities", []):
        lbl = ent["label"]
        txt = ent["text"].strip()
        if lbl == "MalwareTool":
            malware_names.append(txt)
        elif lbl == "Infrastructure_Indicator":
            infra_names.append(txt)
        elif lbl == "ThreatActor":
            threat_actor_names.append(txt)
        elif lbl == "Action":
            action_names.append(txt)

    # Assign confidence by rule
    if threat_actor_names or infra_names :
        conf = 0.7
    if malware_names or tactic_list or technique_list:
        conf = 0.6
    else:
        conf = 0.3

    output_records = []
    # Create one RawCTIRecord per extracted threat actor
    if not threat_actor_names:
        threat_actor_names.append("TA_UNKNOWN")

    if threat_actor_names:
        for ta_name in threat_actor_names:
            # print("=========")
            rec = RawCTIRecord(
                raw_id=raw_id,
                entity_type="threat-actor",
                entity_name=ta_name,
                malware_names=malware_names,
                associated_entity_names=infra_names,
                technique_list=technique_list,
                tactic_list=tactic_list,
                source=source,
                confidence=conf,
                observed_time=default_observed_time,
                report_text=sentence_text,
                procedure=raw_cti_item['procedure']
            )
            output_records.append(rec)

    if not infra_names:
        infra_names.append("INF_UNKNOWN")
    
    if infra_names:
        # unique_infras = list(set(infra_names)) get rid of same infra name in one sentence, but we want to keep them for clustering
        for infra_name in infra_names:
            # print("=========")
            
            infra_rec = RawCTIRecord(
                raw_id=raw_id,
                entity_type="infrastructure",
                entity_name=infra_name,  
                malware_names=malware_names,
                associated_entity_names=threat_actor_names,
                technique_list=technique_list,
                tactic_list=tactic_list,
                source=source,
                confidence=conf,
                observed_time=default_observed_time,
                report_text=sentence_text,
                procedure=raw_cti_item['procedure']
            )
            output_records.append(infra_rec)

    # print("DEBUG: threat_actor_names=", threat_actor_names)
    # print("DEBUG: infra_names=", infra_names)
    # print("output_records",output_records)
    return output_records



# ===================== Helper Functions =====================
def jaccard(set_a: Set, set_b: Set) -> float:
    if not set_a and not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union

def cosine_sim(v1: np.ndarray, v2: np.ndarray) -> float:
    return float(np.dot(v1, v2) / (np.linalg.norm(v1) * np.linalg.norm(v2)))


W_TTP = 0.5
W_GRAPH = 0.25
W_TEXT = 0.25
SCORE_THRESHOLD_AUTO = 0.50
SCORE_THRESHOLD_REVIEW = 0.40
# ===================== Similarity Calculation =====================
def calc_total_sim(r1: RawCTIRecord, r2: RawCTIRecord) -> float:
    
    # print("========Calculating similarity between records========")
    # print("entity names:", r1.entity_name, "and", r2.entity_name)
    # print("r1.technique_list, r2.technique_list:", r1.technique_list, r2.technique_list)
    # print("r1.tactic_list, r2.tactic_list:", r1.tactic_list, r2.tactic_list)

    s_tt = 0.7 * jaccard(r1.technique_list, r2.technique_list) + 0.3 * jaccard(r1.tactic_list, r2.tactic_list)
    s_graph = 0.0
    
    s_malware = 0.0
    for malware in r1.malware_names:
        for malware2 in r2.malware_names:
            malware_emb1 = model.encode(malware, normalize_embeddings=True)
            malware_emb2 = model.encode(malware2, normalize_embeddings=True)
            s_malware += cosine_sim(malware_emb1, malware_emb2)
    s_graph += s_malware/len(r1.malware_names)/len(r2.malware_names) if r1.malware_names and r2.malware_names else 0.0

    s_entity_name = 0.0
    if (r1.entity_name and r2.entity_name) and (r1.entity_name != "TA_UNKNOWN" and r2.entity_name != "TA_UNKNOWN") and (r1.entity_name != "INF_UNKNOWN" and r2.entity_name != "INF_UNKNOWN"):
        entity_emb1 = model.encode(r1.entity_name, normalize_embeddings=True)
        entity_emb2 = model.encode(r2.entity_name, normalize_embeddings=True)
        s_entity_name += cosine_sim(entity_emb1, entity_emb2)
    s_graph += s_entity_name

    s_asso_ent = 0.0
    for associate_entity in r1.associated_entity_names:
            for associate_entity2 in r2.associated_entity_names:
                asso_ent_emb1 = model.encode(associate_entity, normalize_embeddings=True)
                asso_ent_emb2 = model.encode(associate_entity2, normalize_embeddings=True)
                s_asso_ent += cosine_sim(asso_ent_emb1, asso_ent_emb2)
    s_graph += s_asso_ent/len(r1.associated_entity_names)/len(r2.associated_entity_names) if r1.associated_entity_names and r2.associated_entity_names else 0.0

    s_graph /= 3.0  # average the three components
    
    s_proced = cosine_sim(r1.procedure_emb, r2.procedure_emb)
    # print("s_graph:", s_graph)
    # print("s_proced:", s_proced)
    # print("s_tactic:", s_tactic)

    total = W_TTP * s_tt + W_GRAPH * s_graph + W_TEXT * s_proced
    # print("total", total)
    if (r1.entity_name =="Kimsuky group" or r1.entity_name =="Kimsuky group") and (r2.entity_name =="Kimsuky group" or r2.entity_name =="Kimsuky group"):
        print("========Calculating similarity between records========")
        print("entity names:", r1.entity_name, "and", r2.entity_name)
        print("s_tt:", s_tt)
        print("s_graph:", s_graph)
        print("s_proced:", s_proced)
        print("s_malware:", r1.malware_names, r2.malware_names)
        print("associated_entity_names:", r1.associated_entity_names, r2.associated_entity_names)
        print("total", total)
        
    return total
# ===================== Clustering =====================
def cluster_records(records: List[RawCTIRecord]) -> List[List[int]]:
    n = len(records)

    # for r in records:
    #     print("r:",r.entity_type)
    #     print("r:",r.entity_name)
    #     print("r:",r.infra_names)

    
    uf = UnionFind(n)
    for i in range(n):
        ri = records[i]
        for j in range(i + 1, n):
            rj = records[j]
            if ri.entity_type != rj.entity_type:
                continue
            sim = calc_total_sim(ri, rj)
            if sim >= SCORE_THRESHOLD_AUTO:
                uf.union(i, j)
    clusters: Dict[int, List[int]] = {}
    for idx in range(n):
        root = uf.find(idx)
        if root not in clusters:
            clusters[root] = []
        clusters[root].append(idx)
    return list(clusters.values())
# ===================== Format Cluster Output =====================
def format_cluster(cluster_idx_list: List[int], records: List[RawCTIRecord], canon_counter: Dict[str, int]) -> Dict:
    members = [records[i] for i in cluster_idx_list]
    entity_type = members[0].entity_type

    if entity_type == "threat-actor":
        canon_counter["ta"] += 1
        canon_id = f"TA_CAN_{canon_counter['ta']:05d}"
        real_names = [m.entity_name for m in members if m.entity_name != "TA_UNKNOWN"]
        all_names = [m.entity_name for m in members]

        if real_names:
            primary_label = real_names[0]
            aliases = list(set(nm for nm in all_names if nm != primary_label))
        else:
            primary_label = "TA_UNKNOWN"
            aliases = []
    else:
        canon_counter["inf"] += 1
        canon_id = f"INF_CAN_{canon_counter['inf']:05d}"
        real_names = [m.entity_name for m in members if m.entity_name != "INF_UNKNOWN"]
        all_names = [m.entity_name for m in members]

        if real_names:
            primary_label = real_names[0]
            aliases = list(set(nm for nm in all_names if nm != primary_label))
        else:
            primary_label = "INF_UNKNOWN"
            aliases = []

    evidence = []
    for m in members:
        ev = {
            "source": m.source,
            "raw_id": m.raw_id,
            "attributes": {
                "malware_names": sorted(list(m.malware_names)),
                "associated_entity_names": sorted(list(m.associated_entity_names)),
                "ttp": sorted(list(m.technique_list))
            },
            "confidence": m.confidence,
            "observed_time": m.observed_time
        }
        evidence.append(ev)
    evidence.sort(key=lambda x: x["observed_time"])

    all_malware = sorted({x for m in members for x in m.malware_names})
    all_ttp = sorted({x for m in members for x in m.technique_list})
    all_infra = sorted({x for m in members for x in m.associated_entity_names})
    merged_summary = (f"A {entity_type} ({primary_label}) observed using malware: {all_malware}, "
                      f"TTPs: {all_ttp}, associated infrastructure names: {all_infra}")

    return {
        "canonical_id": canon_id,
        "entity_type": entity_type,
        "primary_label": primary_label,
        "aliases": aliases,
        "evidence": evidence,
        "merged_summary": merged_summary,
        "conflicting_claims": []
    }


def print_canonical_entities(final_out: dict):
    print("\n===== Canonical Entity Details =====")
    for ent in final_out["canonical_entities"]:
        print(f"\nCanon ID: {ent['canonical_id']}")
        print(f"Type: {ent['entity_type']}")
        print(f"Primary Label: {ent['primary_label']}")
        print(f"Aliases: {ent['aliases']}")
        print(f"Merged Summary: {ent['merged_summary']}")
        print(f"Evidence count: {len(ent['evidence'])}")
        for idx, ev in enumerate(ent["evidence"]):
            print(f"  - Evidence {idx+1}: raw_id={ev['raw_id']}, source={ev['source']}, confidence={ev['confidence']}")


from pyvis.network import Network

def construct_graph(edges, canonical_entities):
    # build mapping: canon_id -> entity info
    canon2info = {}
    for ent in canonical_entities:
        canon2info[ent["canonical_id"]] = ent

    net = Network(
        height="800px",
        width="100%",
        bgcolor="#ffffff",
        font_color="#000000"
    )

    net.barnes_hut(
        gravity=-4000,
        central_gravity=0.15,
        spring_length=180,
        spring_strength=0.008,
        damping=0.1
    )

    # 【重点：先把所有实体全部加进去，有无边都画】
    for cid, info in canon2info.items():
        etype = info["entity_type"]
        real_name = info["primary_label"]
        aliases = info["aliases"]
        summary = info["merged_summary"]
        tip = f"Canon ID: {cid}\nAliases: {aliases}\n{summary}"

        if etype == "threat-actor":
            color = "#4285F4"   # TA 蓝色
        else:
            color = "#34A853"   # INF 绿色

        net.add_node(
            cid,
            label=real_name,
            title=tip,
            color=color
        )

    # 再加边
    for e in edges:
        head = e["source"]
        tail = e["target"]
        rel = e["relation"]
        net.add_edge(
            head,
            tail,
            title=rel,
            color="#999999",
            width=1
        )

    net.set_options("""
    {
      "physics": {
        "enabled": true,
        "solver": "barnesHut",
        "stabilization": {
          "enabled": true,
          "iterations": 400
        }
      },
      "edges": {
        "smooth": {"enabled": true, "type": "continuous"}
      },
      "interaction": {
        "hover": true,
        "dragNodes": true,
        "zoomView": true,
        "tooltipDelay": 100
      }
    }
    """)

    net.write_html("graph.html")


# ===================== Demo Entry =====================
if __name__ == "__main__":
    with open("./smach_filtered_medium.json", "r", encoding="utf-8") as f:
        data = json.load(f)

    print("loaded data, parsing raw CTI records...")
    raw_inputs = []
    for item in data:
        raw_inputs.extend(parse_raw_cti(item))
    print(f"raw records count: {len(raw_inputs)}")

    print("clustering records...")
    clusters = cluster_records(raw_inputs)
    # print("cluster", clusters)
    print(f"Total clusters formed: {len(clusters)}")

    idx2cluster: Dict[int, int] = {}
    for cid, member_idx_list in enumerate(clusters):
        for idx in member_idx_list:
            idx2cluster[idx] = cid

    counter = {"ta": 0, "inf": 0}
    cid_to_canonid = {}  
    output_list = []
    print("formatting cluster outputs...")
    for cid, member_idx_list in enumerate(clusters):
        out = format_cluster(member_idx_list, raw_inputs, counter)
        cid_to_canonid[cid] = out["canonical_id"]
        output_list.append(out)

    print("mapping infrastructure names to canonical IDs...")
    raw2ta_canon = defaultdict(list)
    raw2inf_canon = defaultdict(list)
    for idx, rec in enumerate(raw_inputs):
        cid = idx2cluster[idx]
        canon_id = cid_to_canonid[cid]   
        if rec.entity_type == "threat-actor":
            raw2ta_canon[rec.raw_id].append(canon_id)
        elif rec.entity_type == "infrastructure":
            raw2inf_canon[rec.raw_id].append(canon_id)

    print("mapping threat-actor canonical IDs to infrastructure canonical IDs...")
    ta_canon_to_infra_canon = defaultdict(set)
    edges = []
    for raw_id, ta_canon_list in raw2ta_canon.items():
        inf_canon_list = raw2inf_canon.get(raw_id, [])
        for ta in ta_canon_list:
            for inf in inf_canon_list:
                if inf not in ta_canon_to_infra_canon[ta]:
                    ta_canon_to_infra_canon[ta].add(inf)
                    edges.append({
                        "source": ta,
                        "target": inf,
                        "relation": "attacks"
                    })

    final_out = {
        "canonical_entities": output_list,
        "ta_infra_edges": edges,
        "ta_canon_to_infra_canon": {k: sorted(list(v)) for k, v in ta_canon_to_infra_canon.items()}
    }

    # print_canonical_entities(final_out)

    final_json = json.dumps(final_out, ensure_ascii=False, indent=2)
    with open("canonical_cti_output.json", "w", encoding="utf-8") as f:
        f.write(final_json)

    # ========== Graph Drawing ==========
    construct_graph(final_out["ta_infra_edges"], final_out["canonical_entities"])
