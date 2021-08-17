// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

/*
#ifdef __linux__
#include <linux/perf_event.h>
#include <sys/sysinfo.h>
#define PERF_EVENT_HEADER_SIZE		(sizeof(struct perf_event_header))
#else
// mocks for Mac
#define PERF_EVENT_HEADER_SIZE		8
#define PERF_RECORD_SAMPLE			9
#define PERF_RECORD_LOST			2

int get_nprocs()
{
	return 1;
}
#endif

*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
)

// PerfEvents is a way to interact with Linux's PerfEvents for eBPF cases.
type PerfEvents struct {
	// Statistics
	EventsReceived   int
	EventsLost       int
	EventsUnknowType int

	// PollTimeoutMs is timeout for blocking call of poll()
	// Defaults to 100ms
	PollTimeoutMs int
	poller        *perfEventPoller

	perfMap        Map
	updatesChannel chan []byte
	stopChannel    chan struct{}
	wg             sync.WaitGroup

	handlers []*perfEventHandler
}

// Go definition for C structs from
// http://man7.org/linux/man-pages/man2/perf_event_open.2.html
// struct perf_event_header {
//     __u32   type;
//     __u16   misc;
//     __u16   size;
// }
type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

// struct perf_event_lost {
//     uint64_t id;
//     uint64_t lost;
// not added: struct sample_id sample_id;
// }
type perfEventLost struct {
	Id   uint64
	Lost uint64
}

// NewPerfEvents creates new instance of PerfEvents for eBPF map "m".
// "m" must be a type of "MapTypePerfEventArray"
func NewPerfEvents(m Map) (*PerfEvents, error) {
	if m.GetType() != MapTypePerfEventArray {
		return nil, fmt.Errorf("Invalid map type '%v'", m.GetType())
	}

	return &PerfEvents{
		perfMap:       m,
		PollTimeoutMs: 100,
	}, nil
}

// StartForAllProcessesAndCPUs starts PerfEvent polling on all CPUs for all system processes
// This mode requires specially organized map: index matches CPU ID.
// "bufferSize" is ring buffer size for perfEvents. Per CPU.
// All updates will be sent into returned channel.
func (pe *PerfEvents) StartForAllProcessesAndCPUs(bufferSize int) (<-chan []byte, error) {
	// Get ONLINE CPU count.
	// There maybe confusion between get_nprocs() and GetNumOfPossibleCpus() functions:
	// - get_nprocs() returns ONLINE CPUs
	// - GetNumOfPossibleCpus() returns POSSIBLE (including currently offline) CPUs
	// So space for eBPF maps should be reserved for ALL possible CPUs,
	// but perfEvents may work only on online CPUs
	nCpus := int(C.get_nprocs())

	// Create perfEvent handler for all possible CPUs
	var err error
	var handler *perfEventHandler
	pe.handlers = make([]*perfEventHandler, nCpus)
	for cpu := 0; cpu < nCpus; cpu++ {
		handler, err = newPerfEventHandler(cpu, -1, bufferSize) // All processes
		if err != nil {
			// Error handling to be done after for loop
			break
		}
		err = pe.perfMap.Update(cpu, int(handler.pmuFd))
		if err != nil {
			// Error handling to be done after for loop
			break
		}
		handler.Enable()
		pe.handlers[cpu] = handler
	}
	// Handle loop errors: release allocated resources / return error
	if err != nil {
		for _, handler := range pe.handlers {
			if handler != nil {
				handler.Release()
			}
		}
		return nil, err
	}

	pe.startLoop()
	return pe.updatesChannel, nil
}

// Stop stops event polling loop
func (pe *PerfEvents) Stop() {
	// Stop poller firstly
	pe.poller.Stop()
	// Stop poll loop
	close(pe.stopChannel)
	// Wait until poll loop stopped, then close updates channel
	pe.wg.Wait()
	close(pe.updatesChannel)

	// Release resources
	for _, handler := range pe.handlers {
		handler.Release()
	}
}

func (pe *PerfEvents) startLoop() {
	pe.stopChannel = make(chan struct{})
	pe.updatesChannel = make(chan []byte)
	pe.wg.Add(1)

	go pe.loop()
}

func (pe *PerfEvents) loop() {
	// Setup poller to poll all handlers (one handler per CPU)
	pe.poller = newPerfEventPoller()
	for _, handler := range pe.handlers {
		pe.poller.Add(handler)
	}

	// Start poller
	pollerCh := pe.poller.Start(pe.PollTimeoutMs)
	defer func() {
		pe.wg.Done()
	}()

	// Wait until at least one perf event fd becomes readable (has new data)
	for {
		select {
		case handler, ok := <-pollerCh:
			if !ok {
				return
			}

			pe.handlePerfEvent(handler)

		case <-pe.stopChannel:
			return
		}
	}
}

func (pe *PerfEvents) handlePerfEvent(handler *perfEventHandler) {
	// Process all new samples at once
	for handler.ringBuffer.DataAvailable() {
		// Read perfEvent header
		var header perfEventHeader
		reader := bytes.NewReader(
			handler.ringBuffer.Read(C.PERF_EVENT_HEADER_SIZE),
		)
		binary.Read(reader, binary.LittleEndian, &header)

		// Read PerfEvent data (header.Size is total size of event: header + data)
		data := handler.ringBuffer.Read(
			int(header.Size - C.PERF_EVENT_HEADER_SIZE),
		)

		// Process event
		switch header.Type {
		case C.PERF_RECORD_SAMPLE:
			// Sample defined as:
			//     struct perf_event_sample {
			//         struct perf_event_header header;
			//         uint32_t data_size;
			//         char data[];
			//     };
			// We've already parsed header, so parse only data_size
			dataSize := binary.LittleEndian.Uint32(data)
			// Send data into channel
			pe.updatesChannel <- data[4 : dataSize+4]
			pe.EventsReceived++

		case C.PERF_RECORD_LOST:
			// This is special record type - contains how many record (events)
			// lost due to small buffer or slow event processing.
			var lost perfEventLost
			reader := bytes.NewReader(data)
			binary.Read(reader, binary.LittleEndian, &lost)
			pe.EventsLost += int(lost.Lost)

		default:
			pe.EventsUnknowType++
		}
	}

	// This is ring buffer: move tail forward to indicate
	// that we've processed some data
	handler.ringBuffer.UpdateTail()
}
