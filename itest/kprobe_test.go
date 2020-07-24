// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package itest

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/dropbox/goebpf"
	"github.com/stretchr/testify/suite"
)

type kprobeTestSuite struct {
	suite.Suite
	programFilename string
	programsCount   int
	mapsCount       int
}

// Basic sanity test of BPF core functionality like
// ReadElf, create maps, load / attach programs
func (ts *kprobeTestSuite) TestElfLoad() {

	eb := goebpf.NewDefaultEbpfSystem()
	err := eb.LoadElf(ts.programFilename)
	ts.Require().NoError(err)

	maps := eb.GetMaps()
	ts.Require().Equal(ts.mapsCount, len(maps))

	perfMap := eb.GetMapByName("perf_map").(*goebpf.EbpfMap)
	ts.Require().NotNil(perfMap)
	ts.NotEqual(0, perfMap.GetFd())
	ts.Equal(goebpf.MapTypePerfEventArray, perfMap.Type)

	ts.Require().Equal(ts.programsCount, len(eb.GetPrograms()))

	// Check that everything loaded correctly / load program into kernel
	for name, program := range eb.GetPrograms() {
		// Check params
		ts.Equal(goebpf.ProgramTypeKprobe, program.GetType())
		ts.Equal(name, program.GetName())
		ts.Equal("GPL", program.GetLicense())
		// Load into kernel
		err = program.Load()
		ts.Require().NoError(err)
		ts.Require().NotEqual(0, program.GetFd())
	}

	// Try to pin program into some filesystem
	kprobe0 := eb.GetProgramByName("kprobe0")
	path := bpfPath + "/kprobe_pin_test"
	err = kprobe0.Pin(path)
	ts.NoError(err)
	ts.FileExists(path)
	os.Remove(path)

	// Non existing program
	ts.Nil(eb.GetProgramByName("something"))

	// Attach program to first (lo) interface
	// P.S. XDP does not work on "lo" interface, however, you can still attach program to it
	// which is enough to test basic BPF functionality
	err = kprobe0.Attach(nil)
	ts.Require().NoError(err)
	err = kprobe0.Detach()
	ts.NoError(err)

	// Attach with parameters
	err = kprobe0.Attach("guess_execve")
	ts.Require().NoError(err)
	err = kprobe0.Detach()
	ts.NoError(err)

	// Unload programs (not required for real use case)
	for _, program := range eb.GetPrograms() {
		err = program.Close()
		ts.NoError(err)
	}

	// Negative: close already closed program
	err = kprobe0.Close()
	ts.Error(err)

	// Negative: attach to non existing symbol
	err = kprobe0.Attach("sys_does_not_exist")
	ts.Error(err)
}

func (ts *kprobeTestSuite) TestKprobeEvents() {

	eb := goebpf.NewDefaultEbpfSystem()
	err := eb.LoadElf(ts.programFilename)
	ts.NoError(err)

	// load and attach kprobes
	for _, program := range eb.GetPrograms() {
		err = program.Load()
		ts.Require().NoError(err)
		ts.Require().NotEqual(0, program.GetFd())
		err = program.Attach(nil)
		ts.Require().NoError(err)
	}

	perfMap := eb.GetMapByName("perf_map").(*goebpf.EbpfMap)
	ts.Require().NotNil(perfMap)
	ts.NotEqual(0, perfMap.GetFd())
	ts.Equal(goebpf.MapTypePerfEventArray, perfMap.Type)

	// Setup/Start perf events
	perfEvents, err := goebpf.NewPerfEvents(perfMap)
	ts.Require().NoError(err)
	perfCh, err := perfEvents.StartForAllProcessesAndCPUs(4096)
	ts.Require().NoError(err)

	// execute process to trigger kprobes
	ts.Require().NoError(exec.Command("whoami").Run())

	cstring := func(b []byte) string {
		off := bytes.Index(b, []byte{0})
		if off < 1 {
			return ""
		}
		return string(b[:off])
	}

	// read perf events
	for i := 0; i < 2; i++ {
		select {
		case data := <-perfCh:
			switch i {
			case 0:
				ts.Require().Equal("itest_test", cstring(data)) // parent comm
			case 1:
				ts.Require().Equal("whoami", cstring(data)) // child comm
			}
		case <-time.After(3 * time.Second):
			ts.Require().Fail("timeout while waiting for perf event")
		}
	}
	perfEvents.Stop()
}

// Run suite
func TestKprobeSuite(t *testing.T) {
	suite.Run(t, &kprobeTestSuite{
		programFilename: "ebpf_prog/kprobe1.elf",
		programsCount:   2,
		mapsCount:       1,
	})
}
