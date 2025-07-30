# stracetools
A Python library for parsing and analyzing strace output

## Sample Data
You can find some sample strace output in the `examples` directory, they are generated using the following command:
- ls.strace.out: `strace -f -tt -T -s 16 -x -a 40 -o examples/ls.strace.out ls -al /`