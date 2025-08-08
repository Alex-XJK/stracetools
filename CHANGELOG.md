# Changelog

All notable changes to this project will be documented here.  
This changelog follows a casual style intended for incremental progress tracking.

## [1.0.0] - 2025-08-08
🎉 First stable release! We believe the existing functionality is solid enough for general use.

## [0.2.1] - 2025-08-08
### Improved
- Enhanced some of the APIs to run in parallel with better performance.

## [0.2.0] - 2025-08-05
### Added
- **Lazy, chainable query interface**:
  ```python
  analyzer.query()
          .by_pid(1234)
          .by_syscall_name(SyscallGroups.FILE_IO)
          .with_success()
          .collect(sort_by_timestamp=True)
  ```
  Gives developers flexibility to build custom filters without being tied to fixed one-off APIs.
### Changed
- Removed some duplicated one-off filter APIs in favor of the chainable interface.

## [0.1.1] - 2025-08-03
### Changed
- License updated from MIT to Apache 2.0.
- Expanded README with detailed API reference.

## [0.1.0] - 2025-08-02
🚀 Initial public release of StraceTools!

### Features
- Complete strace parsing, including unfinished/resumed syscalls.
- Analysis API for filtering by PID, syscall, arguments, time range, and performance metrics.
- Rich statistics: process info, syscall stats, file/network activity.
- Interactive visualizations: Gantt timelines and process activity plots (Plotly-based).

## [0.0.0] - 2025-07-29
The project started as a personal analysis script for research to understand complex strace output and performance bottlenecks in seemingly simple operations.
