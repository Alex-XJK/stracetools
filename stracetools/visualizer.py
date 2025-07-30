from typing import List, Dict, Optional, Set, Tuple, Any
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.express as px
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np

# Assume these are imported from other modules
from .parser import TraceEvent, TraceEventType
from .analyzer import StraceAnalyzer, ProcessInfo


class StraceVisualizer:
    """
    Interactive visualization tools for strace analysis results
    """

    def __init__(self, analyzer: StraceAnalyzer):
        self.analyzer = analyzer
        self.events = analyzer.events

        # Generate consistent colors for syscalls and PIDs
        self.syscall_colors = self._generate_syscall_colors()
        self.pid_colors = self._generate_pid_colors()

    def _generate_syscall_colors(self) -> Dict[str, str]:
        """
        Generate consistent colors for different syscalls
        """
        syscalls = sorted(self.analyzer.get_syscall_names())
        if not syscalls:
            return {}

        # Use a color palette that works well for many categories
        colors = px.colors.qualitative.Set3 + px.colors.qualitative.Pastel + px.colors.qualitative.Set1
        color_cycle = colors * ((len(syscalls) // len(colors)) + 1)

        return {syscall: color_cycle[i] for i, syscall in enumerate(syscalls)}

    def _generate_pid_colors(self) -> Dict[int, str]:
        """
        Generate consistent colors for different PIDs
        """
        pids = sorted(self.analyzer.get_pids())
        if not pids:
            return {}

        colors = px.colors.qualitative.Plotly
        color_cycle = colors * ((len(pids) // len(colors)) + 1)

        return {pid: color_cycle[i] for i, pid in enumerate(pids)}

    def plot_timeline_gantt(self,
                            pids: Optional[List[int]] = None,
                            syscalls: Optional[List[str]] = None,
                            max_events: int = 10000) -> go.Figure:
        """
        Create an interactive Gantt chart showing syscall execution timeline

        Args:
            pids: List of PIDs to include (None for all)
            syscalls: List of syscalls to include (None for all)
            max_events: Maximum number of events to plot

        Returns:
            Plotly Figure object
        """
        # Filter events for plotting
        events = self._filter_events_for_timeline(pids, syscalls, max_events)

        if not events:
            # Return empty figure with message
            fig = go.Figure()
            fig.add_annotation(
                text="No events to display with current filters",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16)
            )
            fig.update_layout(title="Syscall Timeline (No Data)")
            return fig

        # Create figure
        fig = go.Figure()

        # Group events by PID for separate tracks
        filtered_pids = sorted(set(e.pid for e in events))
        pid_to_y = {pid: i for i, pid in enumerate(filtered_pids)}

        # Track which syscalls we've added to legend
        syscalls_in_legend = set()

        for event in events:
            y_pos = pid_to_y[event.pid]
            start_time = event.timestamp
            end_time = start_time + timedelta(seconds=event.duration)

            # Create detailed hover text
            hover_text = self._create_hover_text(event)

            # Determine color and legend settings
            color = self.syscall_colors.get(event.name, '#cccccc')
            show_in_legend = event.name not in syscalls_in_legend
            if show_in_legend:
                syscalls_in_legend.add(event.name)

            # Add rectangle for the syscall duration
            fig.add_trace(go.Scatter(
                x=[start_time, end_time, end_time, start_time, start_time],
                y=[y_pos - 0.4, y_pos - 0.4, y_pos + 0.4, y_pos + 0.4, y_pos - 0.4],
                fill='toself',
                fillcolor=color,
                line=dict(color=color, width=1),
                hovertemplate=hover_text + '<extra></extra>',
                name=event.name,
                showlegend=show_in_legend,
                legendgroup=event.name,
                mode='lines'
            ))

        # Update layout
        fig.update_layout(
            title=f"Syscall Timeline - {len(events)} events across {len(filtered_pids)} processes",
            xaxis_title="Time",
            yaxis_title="Process (PID)",
            yaxis=dict(
                tickmode='array',
                tickvals=list(range(len(filtered_pids))),
                ticktext=[f"PID {pid}" for pid in filtered_pids],
                range=[-0.6, len(filtered_pids) - 0.4]
            ),
            hovermode='closest',
            height=max(400, len(filtered_pids) * 60),
            legend=dict(
                orientation="v",
                yanchor="top",
                y=1,
                xanchor="left",
                x=1.02
            ),
            xaxis=dict(
                type='date',
                tickformat='%H:%M:%S.%3f'
            )
        )

        return fig

    def plot_process_activity(self) -> go.Figure:
        """
        Create an interactive timeline showing process lifetimes and activity levels

        Returns:
            Plotly Figure object
        """
        # Get process information
        process_infos = []
        for pid in self.analyzer.get_pids():
            info = self.analyzer.get_process_info(pid)
            if info:
                process_infos.append(info)

        if not process_infos:
            # Return empty figure with message
            fig = go.Figure()
            fig.add_annotation(
                text="No process data available",
                xref="paper", yref="paper",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=16)
            )
            fig.update_layout(title="Process Activity Timeline (No Data)")
            return fig

        # Sort by first appearance
        process_infos.sort(key=lambda x: x.first_seen)

        fig = go.Figure()

        for i, info in enumerate(process_infos):
            # Calculate process lifetime
            lifetime = info.last_seen - info.first_seen

            # Create hover text with detailed process information
            hover_text = (
                f"<b>PID {info.pid}</b><br>"
                f"<b>Lifetime:</b> {lifetime.total_seconds():.3f}s<br>"
                f"<b>First seen:</b> {info.first_seen.strftime('%H:%M:%S.%f')[:-3]}<br>"
                f"<b>Last seen:</b> {info.last_seen.strftime('%H:%M:%S.%f')[:-3]}<br>"
                f"<b>Total syscalls:</b> {info.syscall_count}<br>"
                f"<b>CPU time:</b> {info.total_duration:.6f}s<br>"
                f"<b>Exit code:</b> {info.exit_code or 'Running/Unknown'}"
            )

            # Add the process lifetime bar
            fig.add_trace(go.Scatter(
                x=[info.first_seen, info.last_seen],
                y=[i, i],
                mode='lines+markers',
                name=f'PID {info.pid}',
                line=dict(
                    width=12,
                    color=self.pid_colors.get(info.pid, '#1f77b4')
                ),
                marker=dict(
                    size=8,
                    symbol=['circle', 'square'],  # Different symbols for start/end
                    color=self.pid_colors.get(info.pid, '#1f77b4')
                ),
                hovertemplate=hover_text + '<extra></extra>',
                showlegend=True
            ))

            # Add a text annotation showing syscall count
            fig.add_annotation(
                x=info.first_seen + (info.last_seen - info.first_seen) / 2,
                y=i,
                text=str(info.syscall_count),
                showarrow=False,
                font=dict(color='white', size=10),
                bgcolor='rgba(0,0,0,0.7)',
                bordercolor='white',
                borderwidth=1
            )

        # Update layout
        fig.update_layout(
            title=f"Process Activity Timeline - {len(process_infos)} processes",
            xaxis_title="Time",
            yaxis_title="Process",
            yaxis=dict(
                tickmode='array',
                tickvals=list(range(len(process_infos))),
                ticktext=[f"PID {info.pid}" for info in process_infos],
                range=[-0.5, len(process_infos) - 0.5]
            ),
            hovermode='closest',
            height=max(400, len(process_infos) * 50),
            xaxis=dict(
                type='date',
                tickformat='%H:%M:%S.%3f'
            ),
            legend=dict(
                orientation="v",
                yanchor="top",
                y=1,
                xanchor="left",
                x=1.02
            )
        )

        return fig

    def _filter_events_for_timeline(self,
                                    pids: Optional[List[int]] = None,
                                    syscalls: Optional[List[str]] = None,
                                    max_events: int = 10000) -> List[TraceEvent]:
        """Filter events for timeline plotting"""
        # Start with syscalls that have duration information
        events = [e for e in self.events
                  if e.event_type == TraceEventType.SYSCALL and e.duration is not None]

        # Apply PID filter
        if pids:
            events = [e for e in events if e.pid in pids]

        # Apply syscall filter
        if syscalls:
            events = [e for e in events if e.name in syscalls]

        # Sort by timestamp and limit
        events.sort(key=lambda x: x.timestamp)
        return events[:max_events]

    @staticmethod
    def _create_hover_text(event: TraceEvent) -> str:
        """
        Create detailed hover text for an event
        """
        hover_lines = [
            f"<b>{event.name}</b>",
            f"<b>PID:</b> {event.pid}",
            f"<b>Start:</b> {event.timestamp.strftime('%H:%M:%S.%f')[:-3]}",
            f"<b>Duration:</b> {event.duration:.6f}s"
        ]

        # Add return value
        if event.return_value:
            hover_lines.append(f"<b>Return:</b> {event.return_value}")

        # Add error if present
        if event.error_msg:
            hover_lines.append(f"<b>Error:</b> {event.error_msg}")

        # Add first few arguments (truncated for readability)
        if event.args:
            args_to_show = event.args[:3]  # Show first 3 args
            truncated_args = []
            for arg in args_to_show:
                if len(arg) > 40:
                    truncated_args.append(arg[:37] + "...")
                else:
                    truncated_args.append(arg)

            args_text = ", ".join(truncated_args)
            if len(event.args) > 3:
                args_text += f", ... (+{len(event.args) - 3} more)"

            hover_lines.append(f"<b>Args:</b> {args_text}")

        return "<br>".join(hover_lines)
