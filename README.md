# StraceTools 🔍

**A modern Python library for parsing, analyzing, and visualizing strace output with ease.**

---

If you find our library useful, please consider starring ⭐ the repository or citing it in your projects! Your support helps us continue improving StraceTools.


## Why StraceTools? 🚀

System debugging and performance analysis often rely on `strace` to understand application behavior. However, existing tools typically fall short:

- **Limited scope**: Most tools only provide basic statistics or file access lists
- **No programmability**: Fixed output formats with no API for custom analysis
- **Poor multi-threading support**: Difficult to analyze concurrent syscall execution
- **No visualization**: Raw text output is hard to interpret for complex applications

**StraceTools bridges these gaps** by providing:

✨ **Comprehensive parsing** with full syscall detail extraction  
🔧 **Programmable API** for custom analysis workflows  
📊 **Interactive visualizations** for timeline and process analysis  
🧵 **Multi-threading support** with process relationship tracking  

## Quick Start 🏃‍♂️

### Getting `strace` Output
To use StraceTools, you first need to generate `strace` output from your application. You can do this by running:

```bash
strace -f -tt -T <other options> -o app_strace.out <your_application>
```

#### Sample Data
You can find some sample strace output in the `examples` directory, they are generated using the following command:
- ls.strace.out: `strace -f -tt -T -s 16 -x -a 40 -o examples/ls.strace.out ls -al /`


### Basic Usage

```python
from stracetools import StraceParser, StraceAnalyzer

# Parse strace output
parser = StraceParser()
events = parser.parse_file("app_strace.out")

# Analyze the results
analyzer = StraceAnalyzer(events)

# Quick insights
print(f"Processes: {len(analyzer.get_pids())}")
print(f"Syscalls: {len(analyzer.get_syscall_names())}")
print(f"Duration: {analyzer.events[-1].timestamp - analyzer.events[0].timestamp}")

# Brief overview
print(analyzer.summary())
```

## Roadmap 🗺️

### Current Status ✅
- [x] Complete strace parsing with multi-threading support
- [x] Comprehensive filtering and analysis API
- [x] Rich statistics and insights
- [x] Interactive timeline Gantt charts
- [x] Process activity visualization

### Coming Soon 🚧
- [ ] **Lazy, chainable query** interface
- [ ] **Official publication** on PyPI
- [ ] **Export to CSV/JSON** for further analysis
- [ ] **Enhance processing speed** for large strace files
- [ ] **Complete visualization suite** (frequency charts, duration histograms)
- [ ] **Integration with profiling tools**

## Requirements 📋

- **Python 3.8+**
- **Core dependencies**: None (pure Python)
- **Visualization** (optional): `matplotlib>=3.5`, `plotly>=5.0`, `numpy>=1.20`

## Contributing 🤝

We welcome contributions! Whether it's:

- 🐛 **Bug reports** and feature requests
- 📖 **Documentation** improvements  
- 🔧 **Code contributions** (parsing improvements, new analysis methods)
- 📊 **Visualization enhancements**


## Key Features 🛠️

### 🎯 **Easy Parsing**

```python
# Initialize parser
parser = StraceParser()

# Parse strace output from a string
event = parser.parse_string("52806 11:11:17.955673 nanosleep({tv_sec=0, tv_nsec=20000}, NULL) = 0 <0.000102>")

# Parse strace output file
events = parser.parse_file("app_strace.out")

```

### 🔍 **Powerful Filtering & Analysis**

```python
# Initialize analyzer with parsed events
analyzer = StraceAnalyzer(events)

# Get all PIDs
pids = analyzer.get_pids()

# Filter by process
events_1234 = analyzer.filter_by_pid(1234)

# Get all syscall names
syscall_names = analyzer.get_syscall_names()

# Filter by syscall with argument matching
file_reads = analyzer.filter_by_syscall("read", args=["file.txt"])

# Filter by event type of signals
signal_events = analyzer.filter_by_event_type(TraceEventType.SIGNAL)

# Time-based filtering
recent_events = analyzer.filter_by_time_range(start_time, end_time)

# Performance analysis
error_calls = analyzer.filter_with_errors()
slow_calls = analyzer.filter_slow_calls(0.01)  # > 10ms
```

### 📊 **Rich Statistics**

```python
# Process information
process_info = analyzer.get_process_info(1234)
print(f"Runtime: {process_info.last_seen - process_info.first_seen}")
print(f"Syscalls: {process_info.syscall_count}")
print(f"CPU time: {process_info.total_duration:.3f}s")

# Syscall statistics
read_stats = analyzer.get_syscall_stats("read")
print(f"Average read duration: {read_stats.avg_duration:.6f}s")
print(f"Error rate: {read_stats.error_count / read_stats.count:.1%}")

# Top syscalls by frequency or duration
top_frequent = analyzer.get_top_syscalls(10, by='count')
top_expensive = analyzer.get_top_syscalls(10, by='duration')

# File operations analysis
file_ops = analyzer.get_file_operations(filename_pattern=r"\.log$")

# Network operations
network_ops = analyzer.get_network_operations()

# Timeline analysis
timeline = analyzer.get_timeline_summary(bucket_size=timedelta(seconds=1))
```

### 📈 **Interactive Visualizations** *(Partial - In Progress)*

```python
visualizer = StraceVisualizer(analyzer, color_map_file="default_colors.json", auto_fillup=False)

# Interactive Gantt chart timeline
gantt_fig = visualizer.plot_timeline_gantt(
    pids=[1234, 5678],              # Filter specific processes
    syscalls=["read", "write"],     # Filter specific syscalls
    max_events=4000,                # Limit for performance
)
gantt_fig.write_html("gantt.html")

# Process activity timeline  
activity_fig = visualizer.plot_process_activity()
activity_fig.show()
```

<img alt="Gantt Chart Example" height="500" src="./docs/filtered_events.svg"/>


## License 📄

MIT License - see [LICENSE](LICENSE) file for details.

---

## Acknowledgments 🙏

Built for developers and system administrators who need deeper insights into application behavior.
Inspired by the need for modern, programmable strace analysis tools.

If you find our library useful, please consider starring ⭐ the repository and citing it in your projects!
Your support helps us continue improving StraceTools.
