import streamlit as st, pandas as pd, time, os
from config import LOG_FILE
st.set_page_config(page_title="MAS Dashboard", layout="wide")
st.title("🛡️ MAS Security Dashboard")
col1, col2 = st.columns(2)
with col1:
    st.subheader("📡 Actions AR")
    logs = [l.strip() for l in open(LOG_FILE).readlines() if l.strip()] if os.path.exists(LOG_FILE) else []
    st.dataframe(pd.DataFrame({"Événement": logs}), height=400)
with col2:
    st.subheader("📊 Métriques")
    blocked = [l for l in logs if "BLOQUÉ" in l]
    st.metric("Alertes", len(logs))
    st.metric("IPs bloquées", len(blocked))
    st.metric("Dernière", blocked[-1].split("|")[1].strip() if blocked else "Aucune")
time.sleep(2); st.rerun()
