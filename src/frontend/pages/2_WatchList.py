import os
import streamlit as st
import pandas as pd
import requests
import matplotlib.pyplot as plt

BASE_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.title("Watch List")

if "df" not in st.session_state:
    st.session_state.df = pd.DataFrame(columns=["CVE", "CWEs", "Severity", "Score"])


def add():
    cve_input = st.session_state.cve_input

    response = requests.get(f"{BASE_URL}/watchlist", params={"cve": cve_input})

    if response.status_code != 200:
        st.error("Failed to load metrics from API")
        st.stop()

    cve_data = response.json()

    if cve_input:
        st.session_state.df.loc[len(st.session_state.df)] = [
            cve_input,
            cve_data[0]["cwes"],
            cve_data[0]["severity"],
            cve_data[0]["score"],
        ]
    else:
        st.warning("CVE is required.")


with st.form("watchlist"):
    st.text_input("Enter CVE ID (e.g., CVE-2024-12345)", key="cve_input")

    st.form_submit_button("Add", on_click=add)


st.dataframe(st.session_state.df, hide_index=True)

COLORS = {
    "background": "#1f1f2e",
    "text": "#f8f9fa",
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#2ecc71",
    "metric_bg": "#2c2c3e",
}

if not st.session_state.df.empty:
    severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_colors = {
        "LOW": COLORS["low"],
        "MEDIUM": COLORS["medium"],
        "HIGH": COLORS["high"],
        "CRITICAL": COLORS["critical"],
    }

    counts = (
        st.session_state.df["Severity"]
        .str.upper()
        .value_counts()
        .reindex(severity_order, fill_value=0)
    )

    fig, ax = plt.subplots(figsize=(8, 4), facecolor=COLORS["background"])
    ax.set_facecolor(COLORS["background"])
    ax.bar(
        counts.index, counts.values, color=[severity_colors[s] for s in counts.index]
    )
    ax.set_xlabel("Severity", color=COLORS["text"])
    ax.set_ylabel("Count", color=COLORS["text"])
    ax.set_title("Watchlist by Severity", color=COLORS["text"], fontsize=14)
    ax.set_yticks(range(0, max(counts.values) + 1))
    ax.tick_params(colors=COLORS["text"])
    for spine in ax.spines.values():
        spine.set_color(COLORS["text"])

    st.pyplot(fig)
