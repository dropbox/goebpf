// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package goebpf

/*
#ifdef __linux__
#include <linux/perf_event.h>
#define PERF_EVENT_HEADER_SIZE		(sizeof(struct perf_event_header))
#else
// mocks for Mac
#define PERF_EVENT_HEADER_SIZE		8
#define PERF_RECORD_SAMPLE			9
#define PERF_RECORD_LOST			2
#endif

*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
)

// PerfEvent is a way to interact with Linux's PerfEvents for eBPF case.
type PerfEvents struct {
	// Statistics
	EventsReceived   int
	EventsLost       int
	EventsUnknowType int

	// PollTimeoutMs is timeout for blocking call of poll()
	// Defaults to 100ms
	PollTimeoutMs int

	perfMap        Map
	updatesChannel chan []byte
	stopChannel    chan bool
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
	// Get CPU count
	nCpus, err := GetNumOfPossibleCpus()
	if err != nil {
		return nil, err
	}

	// Create perfEvent handler for all possible CPUs
	pe.handlers = nil
	for cpu := 0; cpu < nCpus; cpu++ {
		handler, err := newPerfEventHandler(cpu, -1, bufferSize) // All processes
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
		pe.handlers = append(pe.handlers, handler)
	}
	// Handle loop errors: release allocated resources / return error
	if err != nil {
		for _, handler := range pe.handlers {
			handler.Release()
		}
		return nil, err
	}

	pe.startLoop()
	return pe.updatesChannel, nil
}

// Stop stops event polling loop
func (pe *PerfEvents) Stop() {
	// Stop poll loop
	close(pe.stopChannel)
	pe.wg.Wait()

	// Release resources
	for _, handler := range pe.handlers {
		handler.Release()
	}
}

func (pe *PerfEvents) startLoop() {
	pe.stopChannel = make(chan bool)
	pe.updatesChannel = make(chan []byte)
	pe.wg.Add(1)

	go pe.loop()
}

func (pe *PerfEvents) loop() {
	// Setup poller
	poller := newPerfEventPoller()
	for _, handler := range pe.handlers {
		poller.Add(handler)
	}

	// Start poller
	pollerCh := poller.Start(pe.PollTimeoutMs)
	defer func() {
		poller.Stop()
		pe.wg.Done()
	}()

	for {
		select {
		case handler := <-pollerCh:
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

		// Read PerfEvent data
		// header.Size means total size of event: header + data
		data := handler.ringBuffer.Read(
			int(header.Size - C.PERF_EVENT_HEADER_SIZE),
		)

		// Process event
		switch header.Type {
		case C.PERF_RECORD_SAMPLE:
			// PerfEvent Sample. It is defined as
			//     struct perf_event_sample {
			//         struct perf_event_header header;
			//         uint32_t data_size;
			//         char data[];
			//     };
			// We've already parsed header, so parse only data_size and data itself.
			dataSize := binary.LittleEndian.Uint32(data)
			// Send data into channel
			pe.updatesChannel <- data[4 : dataSize+4]
			pe.EventsReceived++

		case C.PERF_RECORD_LOST:
			// This is special record type - contains how many perf events
			// lost due to small buffer or slow event processing
			var lost perfEventLost
			reader := bytes.NewReader(data)
			binary.Read(reader, binary.LittleEndian, &lost)
			pe.EventsLost += int(lost.Lost)

		default:
			pe.EventsUnknowType++
		}
	}

	handler.ringBuffer.UpdateTail()
}
