import os
import streamlit as st
import pandas as pd
import requests

BASE_URL = os.getenv("API_URL", "http://127.0.0.1:8000")

st.title("Your Watch List")

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
