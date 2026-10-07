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
    graph = nx.Graph()
    omitted = 0
    for edge in snapshot["relationships"]:
        left, right = edge["from_node"], edge["to_node"]
        if len(set(graph.nodes) | {left, right}) > 300:
            omitted += 1
            continue
        graph.add_edge(left, right, relation=edge["relation"])
    coordinates = nx.spring_layout(graph, seed=23, iterations=30)
    x, y = [], []
    for left, right in graph.edges:
        x.extend([float(coordinates[left][0]), float(coordinates[right][0]), None])
        y.extend([float(coordinates[left][1]), float(coordinates[right][1]), None])
    lines = go.Scatter(x=x, y=y, mode="lines", hoverinfo="skip", line=dict(color="#68839e", width=1))
    nodes = go.Scatter(x=[float(coordinates[node][0]) for node in graph],
                       y=[float(coordinates[node][1]) for node in graph], mode="markers",
                       text=[html.escape(node) for node in graph], hovertemplate="%{text}<extra></extra>",
                       marker=dict(size=12, color=[graph.degree[node] for node in graph], colorscale="Viridis", showscale=True))
    figure = go.Figure([lines, nodes])
    figure.update_layout(title=f"CyberRecon relationships • {len(graph)} nodes • {omitted} edges omitted by size limit",
                         template="plotly_dark", showlegend=False, dragmode="pan", height=800,
                         xaxis=dict(visible=False), yaxis=dict(visible=False))
    with atomic_output(destination) as temporary:
        figure.write_html(str(temporary), include_plotlyjs=True, full_html=True, config={"scrollZoom": True})
    return str(destination)
