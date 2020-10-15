# Examples

Please note that `eBPF` is supported only by Linux, it will not work on `MacOS`!

## List of examples
- *SocketFilter*: [Simple Packet Counter](https://github.com/dropbox/goebpf/tree/master/examples/socket_filter/packet_counter)
- *XDP*: [Simple packets protocol counter](https://github.com/dropbox/goebpf/tree/master/examples/xdp/packet_counter)
- *XDP*: [Basic Firewall](https://github.com/dropbox/goebpf/tree/master/examples/xdp/basic_firewall)
- *XDP*: [FIB lookup and bpf_redirect example](https://github.com/dropbox/goebpf/tree/master/examples/xdp/bpf_redirect_map)
- *PerfEvents*: [XDP Dump](https://github.com/dropbox/goebpf/tree/master/examples/xdp/xdp_dump)
- *Kprobes*: [Exec Dump](https://github.com/dropbox/goebpf/tree/master/examples/kprobe/exec_dump)

## How to run
All examples actually contain 2 parts:
- The `eBPF` program written in `C`
- `go` application which acts as a control plane

You need to build both to make example work.

### Install prerequisites
```bash
# Install clang/llvm to be able to compile C files into bpf arch
$ apt-get install clang llvm make

# Install goebpf package
$ go get github.com/dropbox/goebpf

```

### Run
Compile both parts
```bash
$ make
clang -I../../.. -O2 -target bpf -c ebpf_prog/xdp.c  -o ebpf_prog/xdp.elf
go build -v -o main
```
Run it!

```bash
$ sudo ./main [optional args]
```
You must use `sudo` or `CAP_SYS_ADMIN` / `CAP_NET_ADMIN` capabilities because of it creates kernel objects.

### How to compile only `eBPF` program
```bash
$ cd [path_to_example]
$ make build_bpf
```
Compiled binary will be under `ebpf_prog` folder, e.g.:
```bash
$ ls -l ebpf_prog
total 8
-rw-r--r-- 1 root root 1524 May 15 21:20 xdp.c
-rw-r--r-- 1 root root 1104 May 15 21:20 xdp.elf
```
