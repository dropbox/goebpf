// Copyright (c) 2020 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

/*
	#ifdef __linux__
		#include <linux/perf_event.h>
		#include <linux/version.h>
		#include <sys/syscall.h>
		#define SYSCALL(...) syscall(__VA_ARGS__)
	#else
		// macOS
		#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
		#define LINUX_VERSION_CODE          266002
		#define SYSCALL(...) (0)
		#define PERF_SAMPLE_RAW             1U << 10
		#define PERF_TYPE_TRACEPOINT        2
		#define PERF_COUNT_SW_BPF_OUTPUT    10
		#define PERF_EVENT_IOC_DISABLE      0
		#define PERF_EVENT_IOC_ENABLE       1
		#define PERF_EVENT_IOC_SET_BPF      8
		#define PERF_FLAG_FD_CLOEXEC        (1UL << 3)
		#define __NR_perf_event_open        364
		struct perf_event_attr {
			int type, config, sample_type, sample_period, wakeup_events;
		};
	#endif

	#include <unistd.h>
	#include <sys/ioctl.h>
	#include "bpf_helpers.h"

	static int kprobe_perf_event_open(int progFd, long id) {

		struct perf_event_attr attr = {};
		attr.config = id;
		attr.type = PERF_TYPE_TRACEPOINT;
		attr.sample_period = 1;
		attr.wakeup_events = 1;
		int pfd = SYSCALL(__NR_perf_event_open, &attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
		if (pfd < 0) {
			//fprintf(stderr, "perf_event_open(%s/id): %s\n", event_path,
			//strerror(errno));
			return -1;
		}

		if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, progFd) < 0) {
			perror("ioctl(PERF_EVENT_IOC_SET_BPF)");
			return -2;
		}
		if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
			perror("ioctl(PERF_EVENT_IOC_ENABLE)");
			return -3;
		}

		return pfd;
	}
*/
import "C"
import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	// namespace provides a unique namespace for kprobe labels
	namespace = "goebpf"
	// sysKprobeEvents
	sysKprobeEvents = "/sys/kernel/debug/tracing/kprobe_events"
	// sysKprobe
	sysKprobe = "/sys/kernel/debug/tracing/events"
	// kretprobeMaxActive
	kretprobeMaxActive = 4096
)

var (
	// kprobeLock enforces synchronous debugfs reads/writes
	kprobeLock sync.Mutex
)

// KprobeAttachType specified whether a Kprobe program is
// attached as an entry or exit probe.
type KprobeAttachType int

const (
	KprobeAttachTypeEntry KprobeAttachType = iota
	KprobeAttachTypeReturn
)

// Prefix returns the string prefix used by debugfs actions.
func (t KprobeAttachType) Prefix() string {
	switch t {
	case KprobeAttachTypeReturn:
		return "r"
	default:
		fallthrough
	case KprobeAttachTypeEntry:
		return "p"
	}
}

// String returns a human readable string for a kprobe attach type.
func (t KprobeAttachType) String() string {
	switch t {
	case KprobeAttachTypeEntry:
		return "kprobe"
	case KprobeAttachTypeReturn:
		return "kretprobe"
	default:
		return "UNKNOWN"
	}
}

// kprobe eBPF program (implements Program interface)
type kprobeProgram struct {
	BaseProgram
	kprobe *kprobe
}

func newProbeProgram(bp BaseProgram, attachType KprobeAttachType) Program {
	// sanity check license
	if bp.GetLicense() != "GPL" {
		fmt.Fprintf(os.Stderr, "ERROR: %s program requires license to be 'GPL'.\n", attachType.String())
		return nil
	}

	// parse and sanity check symbol
	section := bp.GetSection()
	tokens := strings.Split(section, "/")
	if len(tokens) < 2 {
		fmt.Fprintf(os.Stderr, "ERROR: invalid section name e.g. use format '%s/SyS_execve'.\n", attachType.String())
		return nil
	}

	// update base program info
	bp.programType = ProgramTypeKprobe
	bp.kernelVersion = int(C.LINUX_VERSION_CODE)

	return &kprobeProgram{
		BaseProgram: bp,
		kprobe:      newKprobe(attachType, tokens[1]),
	}
}

// newKprobeProgram is a helper to create a new kprobe (entry) program.
func newKprobeProgram(bp BaseProgram) Program {
	return newProbeProgram(bp, KprobeAttachTypeEntry)
}

// newKretprobeProgram is a helper to create a new kprobe (exit) program.
func newKretprobeProgram(bp BaseProgram) Program {
	return newProbeProgram(bp, KprobeAttachTypeReturn)
}

// Attach attaches eBPF(Kprobe) program to a probe point.
// There are 2 possible ways to do that:
//
//  1. Pass attach point as parameter, e.g.
//     xdpProgram.Attach("SyS_execve")
//
//  2. Using the ebpf program section identifier.
//     SEC("kprobe/SyS_execve")
func (p *kprobeProgram) Attach(data interface{}) error {

	// (optional) symbol override by parameter
	switch v := data.(type) {
	case string:
		if len(v) > 0 {
			p.kprobe.symbol = v
		}
	}

	// attempt to attach kprobe to the symbol provided
	if err := p.kprobe.Attach(p.GetFd()); err != nil {
		return err
	}

	// enable the attached kprobe
	if err := p.kprobe.Enable(); err != nil {
		return err
	}

	return nil
}

// Detach detaches program from kprobe attach point.
// Must be previously attached by Attach() call.
func (p *kprobeProgram) Detach() error {
	p.kprobe.Disable()
	return p.kprobe.Detach()
}

// kprobe represents an individual kprobe_event handler.
type kprobe struct {
	// fd is the file descriptor as returned by debugfs
	fd int
	// event is the kprobe entry as written to debugs
	event string
	// symbol is the target symbol to attach the kprobe to (i.e. SyS_execve)
	symbol string
	// attachType is whether the kprobe is attached to the entry or exit point
	attachType KprobeAttachType
}

// newKprobe creates a new kprobe struct and creates debugfs event string.
func newKprobe(attachType KprobeAttachType, sym string) *kprobe {

	p := &kprobe{
		attachType: attachType,
		event:      fmt.Sprintf("%s_%s_%d", sym, namespace, os.Getpid()),
		symbol:     sym,
	}

	return p
}

// kprobePath returns the relevant debugfs path for the kprobe.
func (p *kprobe) kprobePath(cmd string) string {
	return sysKprobe + "/" + p.attachType.String() + "s/" + p.event + "/" + cmd
}

// entry returns the relevant debugfs entry formatted string for the kprobe.
// e.g. r4096:kretprobes/SyS_execve_goebpf_1234 SyS_execve
//
//	<type_prefix|maxactive>:<type>/<label> <target_symbol>
func (p *kprobe) entry() string {
	prefix := p.attachType.Prefix()
	if p.attachType == KprobeAttachTypeReturn {
		prefix += strconv.Itoa(kretprobeMaxActive)
	}
	return fmt.Sprintf("%s:%ss/%s %s", prefix, p.attachType.String(), p.event, p.symbol)
}

// GetFd returns the file descriptor for the kprobe as returned by kprobe_perf_event_open.
func (p *kprobe) GetFd() int {
	return p.fd
}

// GetId returns the kprobe id as returned by debugfs.
func (p *kprobe) GetId() (int, error) {

	// open debugfs path for this kprobe
	data, err := ioutil.ReadFile(p.kprobePath("id"))
	if err != nil {
		return -1, err
	}

	// read kprobe id from debugfs
	id, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return -1, err
	}

	return id, nil
}

// Format returns the debugfs provided format for the kprobe.
func (p *kprobe) Format() (string, error) {

	data, err := ioutil.ReadFile(p.kprobePath("format"))
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// IsEnabled returns the current debugfs /enable state for the kprobe.
func (p *kprobe) IsEnabled() (bool, error) {

	data, err := ioutil.ReadFile(p.kprobePath("enable"))
	if err != nil {
		return false, err
	}

	enabled, err := strconv.ParseBool(strings.TrimSpace(string(data)))
	if err != nil {
		return false, err
	}

	return enabled, nil
}

// Enable sets the /enable flag for the kprobe in debugfs.
func (p *kprobe) Enable() error {
	kprobeLock.Lock()
	defer kprobeLock.Unlock()

	f, err := os.OpenFile(p.kprobePath("enable"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write([]byte("1"))
	if err != nil {
		return err
	}

	return nil
}

// Enable clears the /enable flag for the kprobe in debugfs.
func (p *kprobe) Disable() error {
	kprobeLock.Lock()
	defer kprobeLock.Unlock()

	f, err := os.OpenFile(p.kprobePath("enable"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write([]byte("0"))
	if err != nil {
		return err
	}

	return nil
}

func (p *kprobe) Attach(progFd int) error {
	kprobeLock.Lock()
	defer kprobeLock.Unlock()

	f, err := os.OpenFile(sysKprobeEvents, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	// Helper attach point for basic kernel agnostic programs.
	// Earlier kernel versions will use the prefix 'SyS_' while
	// later kernel versions will use '__x64_sys_'. Specifying
	// the 'guess_' prefix will attempt to attach the kprobe to
	// both of these, returning an error only if both fail.
	prefix := "guess_"
	guesses := []string{"SyS_", "__x64_sys_"}
	var targets []string

	if strings.HasPrefix(p.symbol, prefix) {
		sym := strings.TrimPrefix(p.symbol, prefix)
		for _, guess := range guesses {
			targets = append(targets, guess+sym)
		}
	} else {
		targets = append(targets, p.symbol)
	}

	for _, t := range targets {
		p.symbol = t
		_, err = f.Write([]byte(p.entry()))
		if err != nil {
			continue
		}
		break
	}
	if err != nil {
		return err
	}
	f.Close()

	id, err := p.GetId()
	if err != nil {
		return err
	}

	p.fd = int(C.kprobe_perf_event_open(C.int(progFd), C.long(id)))
	if p.fd < 0 {
		return errors.New("kprobe_perf_event_open")
	}

	return nil
}

func (p *kprobe) Detach() error {
	kprobeLock.Lock()
	defer kprobeLock.Unlock()

	if p.fd <= 0 {
		return errors.New("kprobe: detach invalid fd")
	}
	err := closeFd(p.fd)
	if err != nil {
		return err
	}
	p.fd = 0

	f, err := os.OpenFile(sysKprobeEvents, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write([]byte("-:" + p.event))
	if err != nil {
		return err
	}

	return nil
}

// ListProbes returns a list of the systems attached kprobes as returned by debugfs.
func ListProbes() ([]string, error) {
	data, err := ioutil.ReadFile(sysKprobeEvents)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
}

// CleanupProbes attempts to detach all kprobe entries containing our namespace string.
func CleanupProbes() error {

	probes, err := ListProbes()
	if err != nil {
		return err
	}

	kprobeLock.Lock()
	defer kprobeLock.Unlock()

	for _, p := range probes {
		if p != "" {
			off := strings.Index(p, "/") + 1
			end := strings.Index(p, " ")
			event := p[off:end]
			if strings.Contains(event, namespace) {

				f, err := os.OpenFile(sysKprobeEvents, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					fmt.Fprintf(os.Stderr, "open: %s\n", err)
				}
				defer f.Close()

				_, err = f.Write([]byte("-:" + event))
				if err != nil {
					fmt.Fprintf(os.Stderr, "write: %s\n", err)
				}
			}
		}
	}
	return nil
}
