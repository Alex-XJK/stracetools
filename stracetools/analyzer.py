import re
from collections import defaultdict, Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Set

from .parser import TraceEvent, TraceEventType


@dataclass
class ProcessInfo:
    """
    Information about a process in the trace
    """
    pid: int
    first_seen: datetime
    last_seen: datetime
    syscall_count: int
    total_duration: float
    exit_code: Optional[str] = None


@dataclass
class SyscallStats:
    """
    Statistics for a specific syscall
    """
    name: str
    count: int
    total_duration: float
    avg_duration: float
    min_duration: float
    max_duration: float
    error_count: int
    success_count: int


class StraceAnalyzer:
    """
    Analyzer for parsed strace events with various filtering and analysis capabilities
    """

    def __init__(self, events: List[TraceEvent]):
        self.events = events
        self._build_indices()

    def _build_indices(self):
        """
        Build internal indices for faster lookups
        """
        # Index events by PID
        self.events_by_pid: Dict[int, List[TraceEvent]] = defaultdict(list)

        # Index events by syscall name
        self.events_by_syscall: Dict[str, List[TraceEvent]] = defaultdict(list)

        # Index events by event type
        self.events_by_type: Dict[TraceEventType, List[TraceEvent]] = defaultdict(list)

        # Build indices
        for event in self.events:
            self.events_by_pid[event.pid].append(event)
            self.events_by_type[event.event_type].append(event)

            if event.name:  # syscalls, signals, etc.
                self.events_by_syscall[event.name].append(event)

    def get_pids(self) -> Set[int]:
        """
        Get all PIDs present in the trace

        Returns:
            Set of unique PIDs
        """
        return set(self.events_by_pid.keys())

    def get_syscall_names(self) -> Set[str]:
        """
        Get all syscall names present in the trace

        Returns:
            Set of unique syscall names
        """
        return set(self.events_by_syscall.keys())

    def filter_by_pid(self, pid: int) -> List[TraceEvent]:
        """
        Return all events for a specific PID

        Args:
            pid: Process ID to filter events by

        Returns:
            List of TraceEvent objects for the specified PID
        """
        return self.events_by_pid.get(pid, [])

    def filter_by_syscall(self, syscall_name: str,
                          args: Optional[List[str]] = None,
                          pid: Optional[int] = None) -> List[TraceEvent]:
        """
        Filter events by syscall name and optionally by arguments.

        Args:
            syscall_name: Name of the syscall to filter
            args: List of argument values that must be present in the syscall args
                  (order-independent, partial matching)
            pid: Optional PID to further filter results

        Returns:
            List of matching TraceEvent objects
        """
        # Start with syscall name filter
        candidates = self.events_by_syscall.get(syscall_name, [])

        # Apply PID filter if specified
        if pid is not None:
            candidates = [e for e in candidates if e.pid == pid]

        # Apply argument filter if specified
        if args:
            def matches_args(event_args: List[str], target_args: List[str]) -> bool:
                """
                Check if event args contain all target args
                """
                for target_arg in target_args:
                    if not any(target_arg in event_arg for event_arg in event_args):
                        return False
                return True

            candidates = [e for e in candidates if matches_args(e.args, args)]

        return candidates

    def filter_by_type(self, event_type: TraceEventType) -> List[TraceEvent]:
        """
        Filter events by event type (SYSCALL, SIGNAL, EXIT, etc.)

        Args:
            event_type: The type of event to filter by (TraceEventType)

        Returns:
            List of TraceEvent objects of the specified type
        """
        return self.events_by_type.get(event_type, [])

    def filter_by_time_range(self, start_time: datetime, end_time: datetime) -> List[TraceEvent]:
        """
        Filter events within a specific time range

        Args:
            start_time: Start of the time range
            end_time: End of the time range

        Returns:
            List of TraceEvent objects that fall within the specified time range
        """
        return [e for e in self.events if start_time <= e.timestamp <= end_time]

    def filter_with_errors(self) -> List[TraceEvent]:
        """
        Return only events that had errors

        Returns:
            List of TraceEvent objects that had errors (error_msg is not None)
        """
        return [e for e in self.events if e.error_msg]

    def filter_slow_calls(self, min_duration: float) -> List[TraceEvent]:
        """
        Return syscalls that took longer than min_duration seconds

        Args:
            min_duration: Minimum duration in seconds to filter syscalls

        Returns:
            List of TraceEvent objects that are syscalls with duration >= min_duration
        """
        return [e for e in self.events
                if e.duration and e.duration >= min_duration]

    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """
        Get detailed information about a specific process

        Args:
            pid: Process ID to analyze

        Returns:
            ProcessInfo object with details about the process, or None if not found
        """
        events = self.filter_by_pid(pid)
        if not events:
            return None

        # Find exit event
        exit_events = [e for e in events if e.event_type == TraceEventType.EXIT]
        exit_code = exit_events[0].args[0] if exit_events else None

        # Calculate durations
        syscall_events = [e for e in events if e.event_type == TraceEventType.SYSCALL and e.duration]
        total_duration = sum(e.duration for e in syscall_events)

        return ProcessInfo(
            pid=pid,
            first_seen=min(e.timestamp for e in events),
            last_seen=max(e.timestamp for e in events),
            syscall_count=len([e for e in events if e.event_type == TraceEventType.SYSCALL]),
            total_duration=total_duration,
            exit_code=exit_code
        )

    def get_syscall_stats(self, syscall_name: str, pid: Optional[int] = None) -> Optional[SyscallStats]:
        """
        Get statistics for a specific syscall

        Args:
            syscall_name: Name of the syscall to analyze
            pid: Optional PID to filter results by

        Returns:
            SyscallStats object with statistics for the specified syscall,
            or None if no events found
        """
        events = self.filter_by_syscall(syscall_name, pid=pid)
        if not events:
            return None

        # Only consider completed syscalls with duration
        completed_events = [e for e in events
                            if e.event_type == TraceEventType.SYSCALL and e.duration is not None]

        if not completed_events:
            return None

        durations = [e.duration for e in completed_events]
        error_count = len([e for e in completed_events if e.error_msg])
        success_count = len(completed_events) - error_count

        return SyscallStats(
            name=syscall_name,
            count=len(completed_events),
            total_duration=sum(durations),
            avg_duration=sum(durations) / len(durations),
            min_duration=min(durations),
            max_duration=max(durations),
            error_count=error_count,
            success_count=success_count
        )

    def get_file_operations(self, filename_pattern: Optional[str] = None) -> List[TraceEvent]:
        """
        Get all file-related operations (open, read, write, close, etc.)

        Args:
            filename_pattern: Optional regex pattern to match filenames

        Returns:
            List of TraceEvent objects for file operations
        """
        file_syscalls = ['open', 'openat', 'read', 'write', 'close', 'lseek',
                         'stat', 'fstat', 'lstat', 'access', 'faccessat',
                         'readdir', 'getdents', 'getdents64', 'unlink', 'rmdir',
                         'mkdir', 'rename', 'chmod', 'chown', 'truncate', 'ftruncate']

        file_events = []
        for syscall in file_syscalls:
            file_events.extend(self.filter_by_syscall(syscall))

        # Filter by filename pattern if provided
        if filename_pattern:
            pattern = re.compile(filename_pattern)
            filtered_events = []
            for event in file_events:
                # Check if any argument matches the filename pattern
                for arg in event.args:
                    if pattern.search(arg):
                        filtered_events.append(event)
                        break
            return filtered_events

        return file_events

    def get_network_operations(self) -> List[TraceEvent]:
        """
        Get all network-related operations

        Returns:
            List of TraceEvent objects for network operations
        """
        network_syscalls = ['socket', 'bind', 'listen', 'accept', 'accept4',
                            'connect', 'send', 'recv', 'sendto', 'recvfrom',
                            'sendmsg', 'recvmsg', 'getsockopt', 'setsockopt',
                            'getpeername', 'getsockname', 'shutdown']

        network_events = []
        for syscall in network_syscalls:
            network_events.extend(self.filter_by_syscall(syscall))

        return network_events

    def get_top_syscalls(self, limit: int = 10, by: str = 'count') -> List[tuple]:
        """
        Get top syscalls by count or total duration

        Args:
            limit: Number of top syscalls to return
            by: Sort criteria - 'count' or 'duration'

        Returns:
            List of tuples (syscall_name, value)
        """
        if by == 'count':
            syscall_counts = Counter()
            for event in self.events:
                if event.event_type == TraceEventType.SYSCALL and event.name:
                    syscall_counts[event.name] += 1
            return syscall_counts.most_common(limit)

        elif by == 'duration':
            syscall_durations = defaultdict(float)
            for event in self.events:
                if (event.event_type == TraceEventType.SYSCALL and
                        event.name and event.duration):
                    syscall_durations[event.name] += event.duration

            sorted_durations = sorted(syscall_durations.items(),
                                      key=lambda x: x[1], reverse=True)
            return sorted_durations[:limit]

        else:
            raise ValueError("'by' parameter must be 'count' or 'duration'")

    def get_timeline_summary(self, bucket_size: timedelta = None) -> Dict[datetime, int]:
        """
        Get a timeline summary of syscall activity

        Args:
            bucket_size: Time bucket size for grouping events (default: 100ms)

        Returns:
            Dictionary mapping time buckets to event counts
        """
        if bucket_size is None:
            bucket_size = timedelta(milliseconds=100)

        if not self.events:
            return {}

        # Find time range
        start_time = min(e.timestamp for e in self.events)
        end_time = max(e.timestamp for e in self.events)

        # Create buckets
        timeline = defaultdict(int)

        for event in self.events:
            if event.event_type == TraceEventType.SYSCALL:
                # Calculate which bucket this event belongs to
                time_offset = event.timestamp - start_time
                bucket_index = int(time_offset.total_seconds() / bucket_size.total_seconds())
                bucket_time = start_time + timedelta(seconds=bucket_index * bucket_size.total_seconds())
                timeline[bucket_time] += 1

        return dict(timeline)

    def summary(self) -> str:
        """
        Generate a text summary of the trace

        Returns:
            A string summarizing the trace analysis
        """
        total_events = len(self.events)
        syscall_events = len(self.filter_by_type(TraceEventType.SYSCALL))
        signal_events = len(self.filter_by_type(TraceEventType.SIGNAL))
        exit_events = len(self.filter_by_type(TraceEventType.EXIT))

        pids = self.get_pids()
        syscalls = self.get_syscall_names()

        # Time range
        if self.events:
            start_time = min(e.timestamp for e in self.events)
            end_time = max(e.timestamp for e in self.events)
            duration = end_time - start_time
        else:
            duration = timedelta(0)

        # Top syscalls
        top_syscalls = self.get_top_syscalls(5)

        summary = f"""Strace Analysis Summary
========================
Total Events: {total_events}
- Syscalls: {syscall_events}
- Signals: {signal_events}
- Exits: {exit_events}

Processes: {len(pids)} (PIDs: {sorted(pids)})
Unique Syscalls: {len(syscalls)}
Time Range: {duration.total_seconds():.3f} seconds

Top 5 Syscalls by Count:
"""
        for syscall, count in top_syscalls:
            summary += f"  {syscall}: {count}\n"

        return summary