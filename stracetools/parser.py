import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Dict


logger = logging.getLogger(__name__)


class TraceEventType(Enum):
    """
    Types of trace events that can be parsed from strace output
    """
    SYSCALL = "syscall"
    SIGNAL = "signal"
    EXIT = "exit"
    UNFINISHED = "unfinished"
    RESUMED = "resumed"


@dataclass
class TraceEvent:
    """
    Represents a single trace event (syscall, signal, or exit)
    """
    pid: int
    timestamp: datetime
    event_type: TraceEventType
    name: Optional[str] = None  # syscall name or signal name
    args: List[str] = None  # raw argument strings
    return_value: Optional[str] = None
    error_msg: Optional[str] = None
    duration: Optional[float] = None  # in seconds
    raw_line: str = ""  # keep original line for debugging

    def __post_init__(self):
        if self.args is None:
            self.args = []

    def __str__(self) -> str:
        """
        Human-readable string representation
        """
        timestamp_str = self.timestamp.strftime("%M:%S.%f")  # microsecond precision
        result = f"PID {self.pid} @ {timestamp_str} {self.event_type.value.upper()} --> "

        # Format the main event info
        if self.event_type == TraceEventType.SYSCALL:
            # Show syscall with a few key args
            args_preview = ""
            if self.args:
                # Show first 2 args, truncate long ones
                preview_args = []
                for arg in self.args[:2]:
                    if len(arg) > 30:
                        preview_args.append(arg[:27] + "...")
                    else:
                        preview_args.append(arg)
                args_preview = f"({', '.join(preview_args)}{'...' if len(self.args) > 2 else ''})"

            result += f"{self.name}{args_preview}"

            # Add return value
            if self.return_value:
                result += f" = {self.return_value}"

            # Add error if present
            if self.error_msg:
                result += f" [{self.error_msg}]"

            # Add duration if present
            if self.duration:
                result += f" ~ {self.duration:.6f}s"

        elif self.event_type == TraceEventType.SIGNAL or self.event_type == TraceEventType.EXIT:
            result += f"{self.args[0] if self.args else 'unknown'}"

        else:  # UNFINISHED, RESUMED
            result += f"{self.name}"

        return result

    def time_since(self, other: 'TraceEvent') -> timedelta:
        """
        Calculate time elapsed since another event (self - other)
        """
        return self.timestamp - other.timestamp


class StraceParser:
    """
    Parser for strace output files
    """

    def __init__(self):
        # Track unfinished syscalls by (pid, syscall_name) -> TraceEvent
        self.unfinished_calls: Dict[tuple, TraceEvent] = {}

        # Dummy date for timestamp conversion (since strace only provides time, not date)
        self.base_date = datetime.now().date()

        # Regex patterns for different line types
        self.syscall_pattern = re.compile(
            r'^(\d+)\s+'  # PID
            r'(\d{2}:\d{2}:\d{2}\.\d{6})\s+'  # timestamp
            r'([a-zA-Z_][a-zA-Z0-9_]*)'  # syscall name
            r'\((.*?)\)'  # arguments (non-greedy)
            r'\s*=\s*'  # equals sign
            r'([^<]+?)'  # return value (everything before <duration> or end)
            r'(?:\s*<([0-9.]+)>)?'  # optional duration
            r'\s*$'
        )

        self.unfinished_pattern = re.compile(
            r'^(\d+)\s+'  # PID
            r'(\d{2}:\d{2}:\d{2}\.\d{6})\s+'  # timestamp
            r'([a-zA-Z_][a-zA-Z0-9_]*)'  # syscall name
            r'\((.*?)\s*<unfinished\s*\.\.\.>'  # args with unfinished marker
        )

        self.resumed_pattern = re.compile(
            r'^(\d+)\s+'  # PID
            r'(\d{2}:\d{2}:\d{2}\.\d{6})\s+'  # timestamp
            r'<\.\.\.\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*resumed>'  # syscall name
            r'(.*?)\)'  # remaining arguments
            r'\s*=\s*'  # equals sign
            r'([^<]+?)'  # return value
            r'(?:\s*<([0-9.]+)>)?'  # optional duration
            r'\s*$'
        )

        self.signal_pattern = re.compile(
            r'^(\d+)\s+'  # PID
            r'(\d{2}:\d{2}:\d{2}\.\d{6})\s+'  # timestamp
            r'---\s*(.+?)\s*---'  # signal info
        )

        self.exit_pattern = re.compile(
            r'^(\d+)\s+'  # PID
            r'(\d{2}:\d{2}:\d{2}\.\d{6})\s+'  # timestamp
            r'\+\+\+\s*(.+?)\s*\+\+\+'  # exit info
        )

    def _parse_timestamp(self, time_str: str) -> datetime:
        """
        Convert time string (HH:MM:SS.microseconds) to datetime
        """
        try:
            # Parse the time string
            time_obj = datetime.strptime(time_str, "%H:%M:%S.%f").time()
            # Combine with base date
            return datetime.combine(self.base_date, time_obj)
        except ValueError as e:
            # Fallback: if parsing fails, return current datetime
            logger.warning(f"Failed to parse time string {time_str}: {e}")
            return datetime.now()

    @staticmethod
    def _parse_args(args_str: str) -> List[str]:
        """
        Parse syscall arguments string into a list
        """
        if not args_str.strip():
            return []

        args = []
        current_arg = ""
        paren_depth = 0
        bracket_depth = 0
        brace_depth = 0
        in_quotes = False
        quote_char = None

        i = 0
        while i < len(args_str):
            char = args_str[i]

            # Handle string literals
            if char in ['"', "'"] and (i == 0 or args_str[i - 1] != '\\'):
                if not in_quotes:
                    in_quotes = True
                    quote_char = char
                elif char == quote_char:
                    in_quotes = False
                    quote_char = None

            if not in_quotes:
                if char == '(':
                    paren_depth += 1
                elif char == ')':
                    paren_depth -= 1
                elif char == '[':
                    bracket_depth += 1
                elif char == ']':
                    bracket_depth -= 1
                elif char == '{':
                    brace_depth += 1
                elif char == '}':
                    brace_depth -= 1
                elif char == ',' and paren_depth == 0 and bracket_depth == 0 and brace_depth == 0:
                    args.append(current_arg.strip())
                    current_arg = ""
                    i += 1
                    continue

            current_arg += char
            i += 1

        # Add the last argument
        if current_arg.strip():
            args.append(current_arg.strip())

        return args

    @staticmethod
    def _parse_return_value(return_str: str) -> tuple[str, Optional[str]]:
        """
        Parse return value and optional error message
        """
        return_str = return_str.strip()

        # Check for error patterns like "= -1 EFAULT (Bad address)"
        error_match = re.match(r'^(.+?)\s+([A-Z][A-Z0-9_]*)\s*\((.+?)\)$', return_str)
        if error_match:
            return_val = error_match.group(1)
            error_code = error_match.group(2)
            error_desc = error_match.group(3)
            return return_val, f"{error_code} ({error_desc})"

        # Check for simple error like "= -1 EFAULT"
        error_match = re.match(r'^(.+?)\s+([A-Z][A-Z0-9_]*)$', return_str)
        if error_match and not error_match.group(2).isdigit():
            return error_match.group(1), error_match.group(2)

        return return_str, None

    def parse_line(self, line: str) -> Optional[TraceEvent]:
        """
        Parse a single line of strace output
        """
        line = line.strip()
        if not line:
            return None

        # Try to match different patterns

        # 1. Regular syscall
        match = self.syscall_pattern.match(line)
        if match:
            pid = int(match.group(1))
            timestamp = self._parse_timestamp(match.group(2))
            syscall_name = match.group(3)
            args_str = match.group(4)
            return_str = match.group(5)
            duration_str = match.group(6)

            args = self._parse_args(args_str)
            return_value, error_msg = self._parse_return_value(return_str)
            duration = float(duration_str) if duration_str else None

            return TraceEvent(
                pid=pid,
                timestamp=timestamp,
                event_type=TraceEventType.SYSCALL,
                name=syscall_name,
                args=args,
                return_value=return_value,
                error_msg=error_msg,
                duration=duration,
                raw_line=line
            )

        # 2. Unfinished syscall
        match = self.unfinished_pattern.match(line)
        if match:
            pid = int(match.group(1))
            timestamp = self._parse_timestamp(match.group(2))
            syscall_name = match.group(3)
            args_str = match.group(4)

            args = self._parse_args(args_str)

            event = TraceEvent(
                pid=pid,
                timestamp=timestamp,
                event_type=TraceEventType.UNFINISHED,
                name=syscall_name,
                args=args,
                raw_line=line
            )

            # Store for later completion
            self.unfinished_calls[(pid, syscall_name)] = event
            return None  # Don't return unfinished events immediately

        # 3. Resumed syscall
        match = self.resumed_pattern.match(line)
        if match:
            pid = int(match.group(1))
            timestamp = self._parse_timestamp(match.group(2))
            syscall_name = match.group(3)
            remaining_args = match.group(4)
            return_str = match.group(5)
            duration_str = match.group(6)

            # Find the corresponding unfinished call
            key = (pid, syscall_name)
            if key in self.unfinished_calls:
                unfinished_event = self.unfinished_calls.pop(key)

                # Combine arguments
                if remaining_args.strip():
                    combined_args = unfinished_event.args + self._parse_args(remaining_args)
                else:
                    combined_args = unfinished_event.args

                return_value, error_msg = self._parse_return_value(return_str)
                duration = float(duration_str) if duration_str else None

                # Create completed event
                return TraceEvent(
                    pid=pid,
                    timestamp=unfinished_event.timestamp,  # Use original timestamp
                    event_type=TraceEventType.SYSCALL,
                    name=syscall_name,
                    args=combined_args,
                    return_value=return_value,
                    error_msg=error_msg,
                    duration=duration,
                    raw_line=unfinished_event.raw_line + " | " + line
                )
            else:
                # Orphaned resumed call - create event anyway
                return_value, error_msg = self._parse_return_value(return_str)
                duration = float(duration_str) if duration_str else None

                return TraceEvent(
                    pid=pid,
                    timestamp=timestamp,
                    event_type=TraceEventType.RESUMED,
                    name=syscall_name,
                    args=self._parse_args(remaining_args) if remaining_args.strip() else [],
                    return_value=return_value,
                    error_msg=error_msg,
                    duration=duration,
                    raw_line=line
                )

        # 4. Signal
        match = self.signal_pattern.match(line)
        if match:
            pid = int(match.group(1))
            timestamp = self._parse_timestamp(match.group(2))
            signal_info = match.group(3)

            return TraceEvent(
                pid=pid,
                timestamp=timestamp,
                event_type=TraceEventType.SIGNAL,
                name="SIGNAL",
                args=[signal_info],
                raw_line=line
            )

        # 5. Exit
        match = self.exit_pattern.match(line)
        if match:
            pid = int(match.group(1))
            timestamp = self._parse_timestamp(match.group(2))
            exit_info = match.group(3)

            return TraceEvent(
                pid=pid,
                timestamp=timestamp,
                event_type=TraceEventType.EXIT,
                name="EXIT",
                args=[exit_info],
                raw_line=line
            )

        # If no pattern matches, raise an error
        raise ValueError(f"Unrecognized strace line format: {line}")

    def parse_file(self, filepath: str) -> List[TraceEvent]:
        """
        Parse an entire strace output file
        """
        events = []

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    event = self.parse_line(line)
                    if event:
                        events.append(event)
                except Exception as e:
                    logger.warning(f"Failed to parse line {line_num}: {e}")
                    logger.warning(f"Line {line_num}: {line}")
                    continue

        # Handle any remaining unfinished calls
        for unfinished_event in self.unfinished_calls.values():
            logger.warning(f"Warning: Unfinished syscall without resume: {unfinished_event.name} (PID {unfinished_event.pid})")

        return events
