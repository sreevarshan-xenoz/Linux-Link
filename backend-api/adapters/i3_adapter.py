"""
i3 Window Manager Adapter

Specific adapter for the i3 window manager.
"""

from .i3_sway_adapter import I3Adapter

# Re-export for convenience
__all__ = ['I3Adapter']