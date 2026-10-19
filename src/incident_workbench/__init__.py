"""Incident Evidence Workbench: offline correlations with traceable evidence."""
from .core import InputError, MAX_BYTES, MAX_EVENTS, MAX_LINE_BYTES, analyze, parse_jsonl

__version__ = "0.1.0"
__all__ = ["InputError", "MAX_BYTES", "MAX_EVENTS", "MAX_LINE_BYTES", "analyze", "parse_jsonl"]
