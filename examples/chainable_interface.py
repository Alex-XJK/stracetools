from stracetools import StraceParser, StraceAnalyzer, SyscallGroups

if __name__ == "__main__":
    # Usage example with v0.2.0 new chainable interface
    parser = StraceParser()
    events = parser.parse_file("ls.strace.out")

    analyzer = StraceAnalyzer(events)

    results = (
        analyzer.query()
        .by_pid(993599)
        .by_syscall_name(SyscallGroups.FILE_IO)
        .with_success()
        .collect(sort_by_timestamp=True)
    )
    for result in results:
        print(result)
