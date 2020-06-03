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
	namespace          = "goebpf"
	sysKprobeEvents    = "/sys/kernel/debug/tracing/kprobe_events"
	sysKprobe          = "/sys/kernel/debug/tracing/events"
	kretprobeMaxActive = 4096
)

var (
	kprobeLock sync.Mutex
)

type KprobeAttachType int

const (
	KprobeAttachTypeEntry KprobeAttachType = iota
	KprobeAttachTypeReturn
)

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

type kprobeProgram struct {
	*BaseProgram
	kprobe *kprobe
}

func newProbeProgram(bp *BaseProgram, attachType KprobeAttachType) Program {
	// sanity check license
	if bp.GetLicense() != "GPL" {
		fmt.Fprintf(os.Stderr, "ERROR: %s program requires license to be 'GPL'.\n", attachType.String())
		return nil
	}

	// sanity check target
	target := bp.GetTarget()
	if target == "" {
		fmt.Fprintf(os.Stderr, "ERROR: invalid section name e.g. use format '%s/SyS_execve'.\n", attachType.String())
		return nil
	}

	bp.programType = ProgramTypeKprobe
	bp.kernelVersion = int(C.LINUX_VERSION_CODE)

	return &kprobeProgram{
		BaseProgram: bp,
		kprobe:      newKprobe(attachType, target),
	}
}

func newKprobeProgram(bp *BaseProgram) Program {
	return newProbeProgram(bp, KprobeAttachTypeEntry)
}

func newKretprobeProgram(bp *BaseProgram) Program {
	return newProbeProgram(bp, KprobeAttachTypeReturn)
}

func (p *kprobeProgram) Attach(data interface{}) error {

	// optional target override by parameter
	switch v := data.(type) {
	case string:
		if len(v) > 0 {
			p.kprobe.symbol = v
		}
	}

	if err := p.kprobe.Attach(p.GetFd()); err != nil {
		return err
	}

	if err := p.kprobe.Enable(); err != nil {
		return err
	}

	return nil
}

func (p *kprobeProgram) Detach() error {
	if err := p.kprobe.Disable(); err != nil {
		fmt.Fprintf(os.Stderr, "p.kprobe.Disable(): %s\n", err)
	}
	return p.kprobe.Detach()
}

type kprobe struct {
	fd         int
	event      string
	symbol     string
	attachType KprobeAttachType
}

func newKprobe(attachType KprobeAttachType, sym string) *kprobe {

	p := &kprobe{
		attachType: attachType,
		event:      fmt.Sprintf("%s_%s_%d", sym, namespace, os.Getpid()),
		symbol:     sym,
	}

	return p
}

func (p *kprobe) kprobePath(cmd string) string {
	return sysKprobe + "/" + p.attachType.String() + "s/" + p.event + "/" + cmd
}

func (p *kprobe) entry() string {
	prefix := p.attachType.Prefix()
	if p.attachType == KprobeAttachTypeReturn {
		prefix += strconv.Itoa(kretprobeMaxActive)
	}
	return fmt.Sprintf("%s:%ss/%s %s", prefix, p.attachType.String(), p.event, p.symbol)
}

func (p *kprobe) GetFd() int {
	return p.fd
}

func (p *kprobe) GetId() (int, error) {

	data, err := ioutil.ReadFile(p.kprobePath("id"))
	if err != nil {
		return -1, err
	}

	id, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return -1, err
	}

	return id, nil
}

func (p *kprobe) Format() (string, error) {

	data, err := ioutil.ReadFile(p.kprobePath("format"))
	if err != nil {
		return "", err
	}

	return string(data), nil
}

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

	prefix := "guess_"
	guesses := []string{"SyS_", "__x64_sys_", "do_"}
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

func ListProbes() ([]string, error) {
	data, err := ioutil.ReadFile(sysKprobeEvents)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
}

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
