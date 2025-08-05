import re
from collections import defaultdict, Counter
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Set, Callable, Iterable, Iterator

from .parser import TraceEvent, TraceEventType


class TraceEventQuery:
    """
    A class to lazily and chain filters on a collection of TraceEvent objects.
    """
    def __init__(self, events: Iterable[TraceEvent]):
        self._source = events
        self._filters: list[Callable[[TraceEvent], bool]] = []

    def by_pid(self, pids: int | Collection[int]) -> "TraceEventQuery":
        """
        Filter events by one or more PIDs.
        :since: v0.2.0
        :param pids: An integer PID or a collection of PIDs to filter by.
        """
        if isinstance(pids, int):
            self._filters.append(lambda e: e.pid == pids)
        else:
            pid_set = set(pids)
            self._filters.append(lambda e: e.pid in pid_set)
        return self

    def by_syscall_name(self, names: str | Collection[str]) -> "TraceEventQuery":
        """
        Filter events by one or more syscall names.
        :since: v0.2.0
        :param names: A string syscall name or a collection of syscall names to filter by.
        """
        if isinstance(names, str):
            self._filters.append(lambda e: e.name == names)
        else:
            name_set = set(names)
            self._filters.append(lambda e: e.name in name_set)
        return self

    def by_syscall_args(self, required_args: list[str]) -> "TraceEventQuery":
        """
        Filter events by required arguments in syscall.
        :since: v0.2.0
        :param required_args: A list of argument substrings that must be present in the syscall arguments.
        """
        def _match_args(event_args: list[str], targets: list[str]) -> bool:
            return all(any(t in a for a in event_args) for t in targets)

        self._filters.append(lambda e: _match_args(e.args, required_args))
        return self

    def by_type(self, event_type: TraceEventType) -> "TraceEventQuery":
        """
        Filter events by their type (e.g., SYSCALL, SIGNAL, EXIT).
        :since: v0.2.0
        :param event_type: The TraceEventType to filter by.
        """
        self._filters.append(lambda e: e.event_type == event_type)
        return self

    def by_time_range(self, start: datetime, end: datetime) -> "TraceEventQuery":
        """
        Filter events that occurred within a specific time range.
        :since: v0.2.0
        :param start: Start datetime (inclusive).
        :param end: End datetime (inclusive).
        """
        self._filters.append(lambda e: start <= e.timestamp <= end)
        return self

    def with_errors(self) -> "TraceEventQuery":
        """
        Filter events that resulted in an error (i.e., have a non-null error_msg).
        :since: v0.2.0
        """
        self._filters.append(lambda e: e.error_msg is not None)
        return self

    def with_success(self) -> "TraceEventQuery":
        """
        Filter events that were successful (i.e., have a null error_msg).
        :since: v0.2.0
        """
        self._filters.append(lambda e: e.error_msg is None)
        return self

    def slow_calls(self, min_duration: float) -> "TraceEventQuery":
        """
        Filter events that took longer than a specified duration (in seconds).
        :since: v0.2.0
        :param min_duration: Minimum duration in seconds.
        """
        self._filters.append(lambda e: e.duration is not None and e.duration >= min_duration)
        return self

    def by_filename_regex(self, pattern: str) -> "TraceEventQuery":
        """
        Filter events where any argument matches the given regex pattern.
        :param pattern: Regex pattern to match against syscall arguments.
        """
        regex = re.compile(pattern)
        self._filters.append(lambda e: any(regex.search(arg) for arg in e.args))
        return self

    def __iter__(self) -> Iterator[TraceEvent]:
        return (e for e in self._source if all(f(e) for f in self._filters))

    def collect(self, sort_by_timestamp: bool = True) -> list[TraceEvent]:
        """
        Collect the filtered events into a list, optionally sorted by timestamp.
        :param sort_by_timestamp: Whether to sort the results by timestamp.
        :return: A list of filtered TraceEvent objects.
        """
        results = list(self)
        if sort_by_timestamp:
            results.sort(key=lambda e: e.timestamp)
        return results


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

    def query(self) -> TraceEventQuery:
        """
        Create a query object for filtering events.
        Since v0.2.0, this new lazy and chainable filtering mechanism replaces the older individual filter methods.
        :return: A TraceEventQuery instance for chaining filters
        """
        return TraceEventQuery(self.events)

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


class SyscallGroups:
    FILE_IO = [
        "read", "write", "pread64", "pwrite64", "readv", "writev",
        "splice", "sendfile", "copy_file_range", "fdatasync", "dup", "dup2", "dup3"
    ]

    FILESYSTEM = [
        "open", "openat", "creat", "unlink", "unlinkat", "rename", "renameat",
        "mkdir", "mkdirat", "rmdir", "getdents", "getdents64", "stat", "lstat",
        "fstat", "newfstatat", "access", "chmod", "fchmod", "chown", "truncate", "ftruncate",
        "mount", "umount", "umount2", "link", "symlink", "readlink", "readlinkat",
    ]

    NETWORK = [
        "socket", "connect", "accept", "accept4", "bind", "listen", "getsockname",
        "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown",
        "setsockopt", "getsockopt", "socketpair"
    ]

    PROCESS = [
        "fork", "vfork", "clone", "clone3", "execve", "execveat",
        "wait4", "waitid", "exit", "exit_group", "getpid", "getppid"
    ]

    MEMORY = [
        "mmap", "munmap", "brk", "mremap", "mprotect", "msync", "mlock", "munlock", "madvise"
    ]

    SYNC = [
        "futex", "nanosleep", "clock_nanosleep", "sched_yield"
    ]

    SIGNAL = [
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "kill", "tgkill", "tkill", "sigaltstack"
    ]

    IPC = [
        "shmget", "shmat", "shmdt", "shmctl", "semget", "semop", "semctl",
        "msgget", "msgsnd", "msgrcv", "msgctl", "pipe", "pipe2"
    ]

    IOCTL = [
        "ioctl", "fcntl", "poll", "select", "pselect6", "epoll_wait", "epoll_pwait", "epoll_ctl", "epoll_create1"
    ]

    SECURITY = [
        "capget", "capset", "seccomp", "setuid", "setgid", "setgroups", "setresuid", "setresgid"
    ]

    SYSINFO = [
        "uname", "getrlimit", "setrlimit", "prlimit64", "sysinfo", "gettimeofday", "times"
    ]