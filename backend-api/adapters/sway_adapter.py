"""
Sway Window Manager Adapter

Specific adapter for the Sway window manager.
"""

from .i3_sway_adapter import SwayAdapter

# Re-export for convenience
__all__ = ['SwayAdapter']