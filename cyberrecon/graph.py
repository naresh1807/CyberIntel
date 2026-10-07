"""Offline interactive relationships, with a deterministic size bound."""
import html
from pathlib import Path

import networkx as nx
import plotly.graph_objects as go

from cyberintel.output import atomic_output


def export_graph(snapshot, destination):
    destination = Path(destination)
    if destination.is_symlink():
        raise ValueError("Graph destination cannot be a symlink.")
    graph = nx.DiGraph()
    omitted = 0
    for edge in snapshot["relationships"]:
        left, right = edge["from_node"], edge["to_node"]
        if len(set(graph.nodes) | {left, right}) > 300:
            omitted += 1
            continue
        if graph.has_edge(left, right):
            graph[left][right]["relations"].append(edge["relation"])
        else:
            graph.add_edge(left, right, relations=[edge["relation"]])
    coordinates = nx.spring_layout(graph, seed=23, iterations=30)
    x, y = [], []
    for left, right in graph.edges:
        x.extend([float(coordinates[left][0]), float(coordinates[right][0]), None])
        y.extend([float(coordinates[left][1]), float(coordinates[right][1]), None])
    lines = go.Scatter(x=x, y=y, mode="lines", hoverinfo="skip", line=dict(color="#68839e", width=1))
    evidence = {}
    prefixes = {"assets": ("host:", "ip:"), "subdomains": ("host:", "domain:"),
                "ports": ("port:",), "services": ("service:",), "technologies": ("technology:",),
                "urls": ("url:",), "http": ("url:",), "apis": ("api:",), "javascript": ("url:",)}
    def escaped(value):
        if isinstance(value, str):
            return html.escape(value)
        if isinstance(value, dict):
            return {html.escape(str(key)): escaped(item) for key, item in value.items()}
        if isinstance(value, list):
            return [escaped(item) for item in value]
        return value
    for kind, choices in prefixes.items():
        for row in snapshot.get(kind, []):
            key = row["key"]
            if kind == "services":
                key += ":" + row.get("service", "unknown")
            for prefix in choices:
                node = prefix + key
                if node in graph and len(evidence.setdefault(node, [])) < 10:
                    evidence[node].append(escaped(row))
    details = [{"node": html.escape(node), "observations": evidence.get(node, []),
                "outgoing": [{"node": html.escape(right), "relations": escaped(graph[node][right]["relations"])} for right in graph.successors(node)],
                "incoming": [html.escape(left) for left in graph.predecessors(node)]} for node in graph]
    nodes = go.Scatter(x=[float(coordinates[node][0]) for node in graph],
                       y=[float(coordinates[node][1]) for node in graph], mode="markers",
                       customdata=details, text=[html.escape(node) for node in graph], hovertemplate="%{text}<extra></extra>",
                       marker=dict(size=12, color=[graph.degree[node] for node in graph], colorscale="Viridis", showscale=True))
    figure = go.Figure([lines, nodes])
    figure.update_layout(title=f"CyberRecon relationships • {len(graph)} nodes • {omitted} edges omitted by size limit",
                         template="plotly_dark", showlegend=False, dragmode="pan", height=800,
                         xaxis=dict(visible=False), yaxis=dict(visible=False))
    figure.update_layout(annotations=[dict(ax=float(coordinates[left][0]), ay=float(coordinates[left][1]),
                         x=float(coordinates[right][0]), y=float(coordinates[right][1]),
                         axref="x", ayref="y", xref="x", yref="y", showarrow=True, arrowhead=2,
                         arrowwidth=1, arrowcolor="#68839e", text="") for left, right in list(graph.edges)[:600]])
    script = """const panel = document.createElement('pre');
    panel.style.cssText='white-space:pre-wrap;overflow-wrap:anywhere;padding:20px';
    panel.textContent='Click a node for observations, evidence references and directed relationships (up to 10 observations per node).';
    document.body.appendChild(panel);
    document.getElementById('{plot_id}').on('plotly_click', function(event) {
      const detail = event.points[0].customdata;
      if (detail) panel.textContent = JSON.stringify(detail, null, 2);
    });"""
    with atomic_output(destination) as temporary:
        figure.write_html(str(temporary), include_plotlyjs=True, full_html=True,
                          post_script=script, config={"scrollZoom": True})
    return str(destination)
