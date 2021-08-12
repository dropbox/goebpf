// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

/*
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int perf_events_poll(void *_fds, int cnt, int timeout)
{
    int *fds = _fds;
    int *fds_end = fds + cnt;

    // Allocate N pollfd structs
    size_t pollfds_size = sizeof(struct pollfd) * cnt;
    void *pollfds_memory = malloc(pollfds_size);
    memset(pollfds_memory, 0, pollfds_size);

    // Initialize pollfds from GO array of uint32 fds
    struct pollfd *pollfds = pollfds_memory;
    struct pollfd *pollfds_end = pollfds + cnt;
    for (; fds != fds_end; fds++, pollfds++) {
        pollfds->fd = *fds;
        pollfds->events = POLLIN;
    }
    // Re-set pointers to start of arrays
    pollfds = pollfds_memory;
    fds = _fds;

    int ready_cnt = poll(pollfds, cnt, timeout);

    // Copy all ready descriptors back into golang array of uint32s
    for (int remain = ready_cnt; remain > 0 && pollfds != pollfds_end; pollfds++) {
        if (pollfds->revents & POLLIN) {
            *fds = pollfds->fd;
            fds++;
            remain--;
        }
    }

    free(pollfds_memory);
    return ready_cnt;
}

*/
import "C"
import (
	"sync"
	"unsafe"
)

type perfEventPoller struct {
	items     map[int]*perfEventHandler
	wg        sync.WaitGroup
	fds       []uint32
	timeoutMs int

	stopChannel   chan struct{}
	updateChannel chan *perfEventHandler
}

func newPerfEventPoller() *perfEventPoller {
	return &perfEventPoller{
		items: make(map[int]*perfEventHandler),
	}
}

func (p *perfEventPoller) Add(handler *perfEventHandler) {
	p.items[int(handler.pmuFd)] = handler
}

func (p *perfEventPoller) Start(timeoutMs int) <-chan *perfEventHandler {
	// Create array of uint32 for fds to be used from C function
	p.fds = make([]uint32, len(p.items))
	var idx int
	for fd := range p.items {
		p.fds[idx] = uint32(fd)
		idx++
	}

	// Start poll loop
	p.timeoutMs = timeoutMs
	p.stopChannel = make(chan struct{})
	p.updateChannel = make(chan *perfEventHandler)
	p.wg.Add(1)

	go p.loop()

	return p.updateChannel
}

func (p *perfEventPoller) Stop() {
	// Stop loop
	close(p.stopChannel)
	p.wg.Wait()
	close(p.updateChannel)
}

func (p *perfEventPoller) loop() {
	defer p.wg.Done()

	for {
		// Check stopChannel for close
		select {
		case <-p.stopChannel:
			return
		default:
			break
		}

		// Run poll()
		readyCnt := int(C.perf_events_poll(
			unsafe.Pointer(&p.fds[0]),
			C.int(len(p.items)),
			C.int(p.timeoutMs),
		))

		// Send perfEventHandlers with pending updates, if any
		for i := 0; i < readyCnt; i++ {
			select {
			case p.updateChannel <- p.items[int(p.fds[i])]:

			case <-p.stopChannel:
				return
			}
		}
	}
}
