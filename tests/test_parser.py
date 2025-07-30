from stracetools import StraceParser

sample_lines = [
    '52805 11:11:17.941300 execve("/usr/bin/podman", ["podman", "container", "checkpoint", "man", "-e", "/tmp/manp00.tar", "-c", "none", "--leave-running"], 0x7fff42e4fda8 /* 23 vars */) = 0 <0.000549>',
    '52805 11:11:17.943043 read(3, "\\x7f\\x45\\x4c\\x46\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"..., 832) = 832 <0.000013>',
    '52806 11:11:17.955673 nanosleep({tv_sec=0, tv_nsec=20000},  <unfinished ...>',
    '52806 11:11:17.955780 <... nanosleep resumed>NULL) = 0 <0.000102>',
    '52805 11:11:17.963195 seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_SPEC_ALLOW, NULL) = -1 EFAULT (Bad address) <0.000016>',
    '52831 11:11:18.108785 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_STOPPED, si_pid=40613, si_uid=0, si_status=0, si_utime=14411 /* 144.11 s */, si_stime=2144 /* 21.44 s */} ---',
    '52811 11:11:18.797754 exit_group(0 <unfinished ...>',
    '52811 11:11:18.797804 <... exit_group resumed>) = ?',
    '52809 11:11:18.797864 +++ exited with 0 +++'
]

def test_parser():
    parser = StraceParser()

    print("\n\nTesting parser with sample lines:")
    print("=" * 50)

    events = []
    for i, line in enumerate(sample_lines):
        print(f"\nLine {i + 1}: {line}")
        event = parser.parse_line(line)
        if event:
            events.append(event)
            print(f"  -> {event}")
        else:
            print("  -> Not parsed (likely unfinished)")

    assert len(events) == 7

    print("\n\nTime Calculations:")
    print("=" * 50)
    first_event = events[0]
    last_event = events[-1]

    time_since = last_event.time_since(first_event)

    print(f"First event: {first_event.timestamp.strftime('%H:%M:%S.%f')}")
    print(f"Last event:  {last_event.timestamp.strftime('%H:%M:%S.%f')}")
    print(f"Time elapsed (last - first): {time_since.total_seconds():.6f} seconds")

    assert time_since.microseconds == 1797864 - 941300

def test_file_parsing():
    parser = StraceParser()

    events = parser.parse_file("../examples/ls.strace.out")

    assert len(events) == 722