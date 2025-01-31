import os
import streamlit.components.v1 as components

# Minimal no-build component for chunked client-side mining
_component_func = components.declare_component(
    "my_pow",
    path=os.path.dirname(__file__)  # folder containing index.html
)

def my_pow(**kwargs):
    """
    The Python wrapper. You pass in difficulty_bits, chunk_size, etc.
    Returns a dict from JavaScript, or None if no result yet.
    """
    return _component_func(**kwargs)
