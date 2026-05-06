import streamlit as st
import requests
from datetime import datetime
import matplotlib.pyplot as plt
import networkx as nx

# =====================
# Page Config
# =====================
st.set_page_config(page_title="CVE Dashboard", page_icon="🛡️", layout="wide")

COLORS = {
    "background": "#1f1f2e",
    "text": "#f8f9fa",
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#2ecc71",
    "metric_bg": "#2c2c3e",
}
st.markdown(
    f"<h1 style='text-align:center; color:{COLORS['text']}; font-size:28px;'>E Corp Threat Hub</h1>",
    unsafe_allow_html=True,
)
st.markdown("---")

# =====================
# Slider for last N days
# =====================
days = st.slider(
    "Select number of past days to analyze:", min_value=1, max_value=30, value=7
)
st.markdown(
    f"<h1 style='text-align:center;font-size:22px;'>Last {days} Day(s)</h1>",
    unsafe_allow_html=True,
)
# =====================
# Fetch metrics from FastAPI
# =====================
BASE_URL = "http://127.0.0.1:8000"
response = requests.get(f"{BASE_URL}/cves/summary", params={"days": days})

if response.status_code != 200:
    st.error("Failed to load metrics from API")
    st.stop()

cve_data = response.json()

# Metrics
total_cves = cve_data["metrics"]["total"]
critical_cves = cve_data["metrics"]["critical"]
average_cvss = round(cve_data["metrics"]["average_cvss"], 2)
kev_ratio = cve_data["metrics"]["kev_ratio"]

tab_cve, tab_kev = st.tabs(["CVEs", "KEVs"])

with tab_cve:
    with st.container():
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total CVEs", total_cves)
        col2.metric("Critical CVEs", critical_cves)
        col3.metric("Average CVSS", average_cvss)
        col4.metric("KEV Risk Ratio", f"{kev_ratio:.2%}")
    st.markdown("---")

    # =====================
    # Severity Pie Chart
    # =====================
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_counts = cve_data["severity_counts"]
    counts = [severity_counts.get(s, 0) for s in severities]

    fig, ax = plt.subplots(figsize=(8, 4), facecolor=COLORS["background"])
    colors = [COLORS["critical"], COLORS["high"], COLORS["medium"], COLORS["low"]]
    ax.pie(
        counts,
        labels=severities,
        autopct="%1.1f%%",
        startangle=140,
        colors=colors,
        textprops={"color": COLORS["text"], "fontsize": 12},
    )
    ax.set_title("CVEs by Severity", color=COLORS["text"], fontsize=14)
    ax.axis("equal")
    ax.legend(
        [f"{s}: {c}" for s, c in zip(severities, counts)],
        loc="lower right",
        facecolor=COLORS["metric_bg"],
        labelcolor=COLORS["text"],
    )
    st.pyplot(fig)

    # =====================
    # Weekday Stacked Bar Chart
    # =====================
    weekday_totals = cve_data["weekday_counts"]
    labels = list(weekday_totals.keys())

    critical = [weekday_totals[d].get("CRITICAL", 0) for d in labels]
    high = [weekday_totals[d].get("HIGH", 0) for d in labels]
    medium = [weekday_totals[d].get("MEDIUM", 0) for d in labels]
    low = [weekday_totals[d].get("LOW", 0) for d in labels]

    fig2, ax = plt.subplots(figsize=(12, 6), facecolor=COLORS["background"])
    ax.bar(labels, critical, label="CRITICAL", color=COLORS["critical"])
    ax.bar(labels, high, bottom=critical, label="HIGH", color=COLORS["high"])
    ax.bar(
        labels,
        medium,
        bottom=[c + h for c, h in zip(critical, high)],
        label="MEDIUM",
        color=COLORS["medium"],
    )
    ax.bar(
        labels,
        low,
        bottom=[c + h + m for c, h, m in zip(critical, high, medium)],
        label="LOW",
        color=COLORS["low"],
    )

    ax.set_title("CVEs by Day and Severity", color=COLORS["text"], fontsize=12)
    ax.set_ylabel("Number of CVEs", color=COLORS["text"], fontsize=12)
    ax.tick_params(axis="x", colors=COLORS["text"], rotation=90)
    ax.tick_params(axis="y", colors=COLORS["text"])
    ax.legend(facecolor=COLORS["metric_bg"], labelcolor=COLORS["text"])
    ax.spines["bottom"].set_color(COLORS["text"])
    ax.spines["top"].set_color(COLORS["text"])
    ax.spines["left"].set_color(COLORS["text"])
    ax.spines["right"].set_color(COLORS["text"])
    st.pyplot(fig2)

response = requests.get(f"{BASE_URL}/kevs/summary", params={"days": days})

if response.status_code != 200:
    st.error("Failed to load metrics from API")
    st.stop()

kev_data = response.json()
total_kevs = kev_data["metrics"]["total"]
top_vendor = kev_data["metrics"]["top_vendor"]
most_common_cwe = kev_data["metrics"]["most_common_cwe"]
ransomware_campaigns = kev_data["metrics"]["ransomware_campaigns"]
graph_data = kev_data["network_graph"]
cwe_counts = kev_data["cwe_counts"]

with tab_kev:
    with st.container():
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total KEVs", total_kevs)
        col2.metric("Top Vendor", top_vendor)
        col3.metric("Most Common CWE", most_common_cwe)
        col4.metric("Active Ransomware", ransomware_campaigns)
    st.markdown("---")

    # Build Graph: CWE -> Vendor with product as edge label
    G = nx.DiGraph()

    # Add nodes
    for node in graph_data["nodes"]:
        G.add_node(node["id"], type=node["type"])

    # Add edges
    for edge in graph_data["edges"]:
        source = edge["source"]
        target = edge["target"]
        product = edge.get("product", "")
        # Concatenate multiple products if same edge appears multiple times
        if G.has_edge(source, target):
            G[source][target]["label"] += f", {product}"
            if edge.get("ransomware") == "Known":
                G[source][target]["ransomware"] = "Known"
        else:
            G.add_edge(
                source,
                target,
                label=product,
                ransomware=edge.get("ransomware", "Unknown"),
            )

    # =====================
    # Layout: CWE top, Vendor bottom
    # =====================
    cwe_nodes = [n for n, d in G.nodes(data=True) if d["type"] == "cwe"]
    vendor_nodes = [n for n, d in G.nodes(data=True) if d["type"] == "vendor"]

    pos = {}
    # Spread nodes horizontally
    for i, n in enumerate(cwe_nodes):
        pos[n] = (i * 3, 1)  # CWE layer
    for i, n in enumerate(vendor_nodes):
        pos[n] = (i * 3, 0)  # Vendor layer

    # Node colors
    color_map = []
    for n in G.nodes:
        color_map.append("salmon" if G.nodes[n]["type"] == "cwe" else "lightblue")

    # Edge colors
    edge_colors = [
        "red" if d.get("ransomware") == "Known" else "gray"
        for u, v, d in G.edges(data=True)
    ]

    # =====================
    # Draw Graph
    # =====================
    fig4 = plt.figure(figsize=(max(30, len(G.nodes) * 0.5), 12))

    nx.draw_networkx_nodes(G, pos, node_color=color_map, node_size=1200)
    nx.draw_networkx_labels(G, pos, font_size=10)
    nx.draw_networkx_edges(G, pos, edge_color=edge_colors)

    edge_labels = nx.get_edge_attributes(G, "label")
    nx.draw_networkx_edge_labels(
        G, pos, edge_labels=edge_labels, font_color="black", font_size=9
    )

    plt.title(
        "CWE → Vendor Network (Product as Edge Label, Red = Ransomware)", fontsize=14
    )
    plt.axis("off")

    st.pyplot(fig4)

    # =====================
    # CWE Bar Chart
    # =====================

    if cwe_counts:
        fig3, ax = plt.subplots(figsize=(12, 6))

        labels = list(cwe_counts.keys())
        values = list(cwe_counts.values())

        ax.barh(labels, values)

        ax.set_title("CWEs in KEVs")
        ax.set_xlabel("Number of KEVs")
        ax.set_ylabel("CWE")
        ax.set_xlim(0, 10)
        ax.set_xticks(range(0, 11))

        st.pyplot(fig3)

# =====================
# Last updated
# =====================
st.markdown("---")
st.markdown(
    f"<p style='color:{COLORS['text']}; text-align:center'>Last Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>",
    unsafe_allow_html=True,
)
