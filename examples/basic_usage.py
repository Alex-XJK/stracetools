from stracetools import StraceParser, StraceAnalyzer, StraceVisualizer

if __name__ == "__main__":
    # Usage example
    parser = StraceParser()
    events = parser.parse_file("ls.strace.out")
    analyzer = StraceAnalyzer(events)
    print(analyzer.summary())

    visualizer = StraceVisualizer(analyzer, color_map_file="../stracetools/default_syscall_colors.json", auto_fillup=False)

    # Timeline for all syscalls
    print("Generating timeline for all syscalls...")
    fig1 = visualizer.plot_timeline_gantt(max_events=10000)
    fig1.show()

    # Timeline for selected syscalls
    print("Generating timeline for selected syscalls...")
    all_syscalls = analyzer.get_syscall_names()
    filtered_syscalls = [s for s in all_syscalls if s not in ["futex", "nanosleep", "epoll_wait", "epoll_pwait", "wait4", "waitid"]]
    fig2 = visualizer.plot_timeline_gantt(max_events=5000, syscalls=filtered_syscalls)
    fig2.show()
    fig2.write_html("fig2.html")

    # Live-time for each process
    print("Generating process activity plot...")
    fig3 = visualizer.plot_process_activity()
    fig3.show()
    fig3.write_image("fig3.svg")
