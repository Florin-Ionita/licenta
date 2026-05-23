"""Plotly figure builders for the four dashboard panels.

Each builder is a pure function: bus snapshot in, ``plotly.graph_objects.Figure``
out. Keeping them pure makes them trivially testable and side-effect-free under
Streamlit's rerun model.
"""
