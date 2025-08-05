"""
Strace Tools - A Python library for parsing and analyzing strace output
"""

__version__ = "0.2.0"
__author__ = "Alex Jiakai Xu"
__email__ = "jiakai.xu@columbia.edu"

# Import main classes for easy access
from .parser import TraceEventType, TraceEvent, StraceParser
from .analyzer import ProcessInfo, SyscallStats, StraceAnalyzer, SyscallGroups, TraceEventQuery
from .visualizer import StraceVisualizer

__all__ = [
    "TraceEventType",
    "TraceEvent",
    "StraceParser",
    "ProcessInfo",
    "SyscallStats",
    "StraceAnalyzer",
    "StraceVisualizer",
    "SyscallGroups",        # Since v0.2.0
    "TraceEventQuery",      # Since v0.2.0
]