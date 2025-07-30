from stracetools import StraceParser, StraceAnalyzer

def test_analyzer_basic():
    parser = StraceParser()
    events = parser.parse_file("../examples/ls.strace.out")
    analyzer = StraceAnalyzer(events)

    print("\nRunning basic analyzer tests...\n")

    pids = analyzer.get_pids()
    assert pids == {993599}

    syscalls = analyzer.get_syscall_names()
    assert len(syscalls) == 31

    non_existent_pid_events = analyzer.filter_by_pid(1)
    assert len(non_existent_pid_events) == 0

    write_info = analyzer.get_syscall_stats("write")
    assert write_info.count == 26

    print(analyzer.summary())