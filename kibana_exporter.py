#!/usr/bin/env python3
import argparse, logging, os, tempfile, pandas as pd, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from elasticsearch import Elasticsearch
from fpdf import FPDF
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch(es_url, index, days):
    es = Elasticsearch(es_url)
    start = (datetime.now()-timedelta(days=days)).isoformat()
    res = es.search(index=index, query={"range":{"@timestamp":{"gte":start}}}, size=10000, sort=[{"@timestamp":"desc"}])
    return [h["_source"] for h in res["hits"]["hits"]]

def flatten(data):
    out=[]
    for d in data:
        e=d.get("extra",{})
        out.append({"timestamp":d.get("@timestamp"),"threat":e.get("threat_type","N/A"),"ip":e.get("source_ip","?"),
                     "mitre":e.get("mitre",{}).get("technique_id","?"),"score":e.get("risk_score",0),"status":e.get("status","?")})
    df=pd.DataFrame(out); df["timestamp"]=pd.to_datetime(df["timestamp"],errors="coerce")
    return df.dropna(subset=["threat"])

def export_pdf(df, outdir, days):
    p=os.path.join(outdir, f"mas_{datetime.now():%Y%m%d_%H%M}.pdf")
    class Rep(FPDF):
        def header(self): self.set_font("Helvetica","B",12); self.cell(0,10,"MAS Security Report",align="C",new_x="LMARGIN",new_y="NEXT"); self.ln(4)
        def footer(self): self.set_y(-15); self.set_font("Helvetica","I",8); self.cell(0,10,f"Page {self.page_no()}/{{nb}}",align="C")
    pdf=Rep(); pdf.add_page()
    pdf.set_font("Helvetica","B",10); pdf.cell(0,8,f"Période: {days}j | Alertes: {len(df)}",new_x="LMARGIN",new_y="NEXT"); pdf.ln(5)
    tmp=tempfile.mkdtemp()
    plt.figure(); df["mitre"].value_counts().head(5).plot(kind="bar",color="#2E7D32"); plt.tight_layout()
    i1=f"{tmp}/m.png"; plt.savefig(i1,dpi=120); plt.close(); pdf.image(i1,w=180); pdf.ln(5)
    pdf.set_font("Helvetica","",9)
    for _,r in df.head(20).iterrows(): pdf.cell(0,5,f"{r['timestamp']} | {r['threat']} | {r['ip']} | {r['mitre']} | S:{r['score']}",new_x="LMARGIN",new_y="NEXT")
    pdf.output(p); logger.info(f"📕 PDF: {p}")
    return p

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--es",default="http://localhost:9200"); ap.add_argument("--index",default="mas-alerts")
    ap.add_argument("--days",type=int,default=7); ap.add_argument("--out",default="./reports"); ap.add_argument("--fmt",choices=["csv","pdf","both"],default="both")
    a=ap.parse_args(); os.makedirs(a.out,exist_ok=True)
    data=fetch(a.es, a.index, a.days)
    if not data: logger.warning("Aucune donnée."); return
    df=flatten(data)
    if a.fmt in ["csv","both"]: pd.DataFrame(df).to_csv(f"{a.out}/mas.csv",index=False); logger.info("📄 CSV généré")
    if a.fmt in ["pdf","both"]: export_pdf(df, a.out, a.days)

if __name__=="__main__": main()
