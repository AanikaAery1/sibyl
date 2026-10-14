"""Sibyl MCP server (D53): lets an MCP-capable assistant act as an external monitor.

``sibyl-mcp`` (stdio by default, or ``--transport streamable-http``) exposes the fleet's
metadata and an advisory ``submit_finding`` over a monitor-bound key from ``SIBYL_MONITOR_KEY``.
"""

from __future__ import annotations

__version__ = "0.1.0.dev0"

__all__ = ["__version__"]
