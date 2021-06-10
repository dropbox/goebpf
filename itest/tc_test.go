// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package itest

import (
	"os"
	"testing"
	"time"

	"github.com/dropbox/goebpf"
	"github.com/stretchr/testify/suite"
)

const (
	tcProgramFilename = "ebpf_prog/tc1.elf"
)

type tcTestSuite struct {
	suite.Suite
	programFilename string
	programsCount   int
}

// Basic sanity test of BPF core functionality like
// ReadElf, create maps, load / attach programs
func (ts *tcTestSuite) TestElfLoad() {
	// This compile ELF file contains 2 BPF(TC type) programs
	eb := goebpf.NewDefaultEbpfSystem()
	err := eb.LoadElf(ts.programFilename)
	ts.NoError(err)
	if err != nil {
		// ELF read error.
		ts.FailNowf("Unable to read %s", ts.programFilename)
	}

	// There should be 0 BPF maps recognized by loader
	maps := eb.GetMaps()
	ts.Require().Equal(0, len(maps))

	// Non existing map
	ts.Nil(eb.GetMapByName("something"))

	// Also there should few TC eBPF programs recognized
	ts.Require().Equal(ts.programsCount, len(eb.GetPrograms()))

	// Check loaded programs and try to pin them
	tc1 := eb.GetProgramByName("tc1")
	tc1.Load()
	path := bpfPath + "/tc1_pin_test"
	err = tc1.Pin(path)
	ts.NoError(err)
	ts.FileExists(path)
	os.Remove(path)
	ts.Equal(goebpf.ProgramTypeSchedCls, tc1.GetType())

	// Check loaded programs and try to pin them
	tc2 := eb.GetProgramByName("tc2")
	tc2.Load()
	path = bpfPath + "/tc2_pin_test"
	err = tc2.Pin(path)
	ts.NoError(err)
	ts.FileExists(path)
	os.Remove(path)
	ts.Equal(goebpf.ProgramTypeSchedAct, tc2.GetType())

	// Check loaded programs and try to pin them
	tc3 := eb.GetProgramByName("tc3")
	tc3.Load()
	path = bpfPath + "/tc3_pin_test"
	err = tc3.Pin(path)
	ts.NoError(err)
	ts.FileExists(path)
	os.Remove(path)
	ts.Equal(goebpf.ProgramTypeSchedAct, tc3.GetType())

	// Non existing program
	ts.Nil(eb.GetProgramByName("something"))

	//Run attach and detach, they shouldn't fail as these methods are not implemented for TC
	err = tc1.Attach(0)
	ts.Error(err)
	err = tc1.Detach()
	ts.Error(err)
	err = tc2.Attach(0)
	ts.Error(err)
	err = tc2.Detach()
	ts.Error(err)
	err = tc3.Attach(0)
	ts.Error(err)
	err = tc3.Detach()
	ts.Error(err)

	// Unload programs (not required for real use case)
	for _, program := range eb.GetPrograms() {
		err = program.Close()
		ts.NoError(err)
	}

	// Negative: close already closed program
	err = tc1.Close()
	ts.Error(err)

}

func (ts *tcTestSuite) TestProgramInfo() {
	// Load test program, don't attach (not required to get info)
	eb := goebpf.NewDefaultEbpfSystem()
	err := eb.LoadElf(ts.programFilename)
	ts.Require().NoError(err)
	prog := eb.GetProgramByName("tc1")
	err = prog.Load()
	ts.Require().NoError(err)

	// Get program info by FD (NOT ID, since this program is ours)
	info, err := goebpf.GetProgramInfoByFd(prog.GetFd())
	ts.NoError(err)

	// Check base info
	ts.Equal(prog.GetName(), info.Name)
	ts.Equal(prog.GetFd(), info.Fd)
	ts.Equal(goebpf.ProgramTypeSchedCls, info.Type)
	// Check loaded time
	now := time.Now()
	ts.True(now.Sub(info.LoadTime) < time.Second*10)

}

// Run suite
func TestTcSuite(t *testing.T) {
	suite.Run(t, &tcTestSuite{
		programFilename: tcProgramFilename,
		programsCount:   3,
	})
}
