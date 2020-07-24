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
	xdpProgramFilename = "ebpf_prog/xdp1.elf"
)

type xdpTestSuite struct {
	suite.Suite
	programFilename string
	programsCount   int
	mapsCount       int
}

// Basic sanity test of BPF core functionality like
// ReadElf, create maps, load / attach programs
func (ts *xdpTestSuite) TestElfLoad() {
	// This compile ELF file contains 2 BPF(XDP type) programs with 2 BPF maps
	eb := goebpf.NewDefaultEbpfSystem()
	err := eb.LoadElf(ts.programFilename)
	ts.NoError(err)
	if err != nil {
		// ELF read error.
		ts.FailNowf("Unable to read %s", ts.programFilename)
	}

	// There should be 6 BPF maps recognized by loader
	maps := eb.GetMaps()
	ts.Require().Equal(ts.mapsCount, len(maps))

	txcnt := maps["txcnt"].(*goebpf.EbpfMap)
	ts.NotEqual(0, txcnt.GetFd())
	ts.Equal(goebpf.MapTypePerCPUArray, txcnt.Type)
	ts.Equal(4, txcnt.KeySize)
	ts.Equal(8, txcnt.ValueSize)
	ts.Equal(100, txcnt.MaxEntries)
	ts.Equal("/sys/fs/bpf/txcnt", txcnt.PersistentPath)

	rxcnt := maps["rxcnt"].(*goebpf.EbpfMap)
	ts.NotEqual(0, rxcnt.GetFd())
	ts.Equal(goebpf.MapTypeHash, rxcnt.Type)
	ts.Equal(8, rxcnt.KeySize)
	ts.Equal(4, rxcnt.ValueSize)
	ts.Equal(50, rxcnt.MaxEntries)

	moftxcnt := maps["match_maps_tx"].(*goebpf.EbpfMap)
	ts.NotEqual(0, moftxcnt.GetFd())
	ts.Equal(goebpf.MapTypeArrayOfMaps, moftxcnt.Type)
	ts.Equal(4, moftxcnt.KeySize)
	ts.Equal(4, moftxcnt.ValueSize)
	ts.Equal(10, moftxcnt.MaxEntries)

	mofrxcnt := maps["match_maps_rx"].(*goebpf.EbpfMap)
	ts.NotEqual(0, mofrxcnt.GetFd())
	ts.Equal(goebpf.MapTypeHashOfMaps, mofrxcnt.Type)
	ts.Equal(4, mofrxcnt.KeySize)
	ts.Equal(4, mofrxcnt.ValueSize)
	ts.Equal(20, mofrxcnt.MaxEntries)
	ts.Equal("/sys/fs/bpf/match_maps_rx", mofrxcnt.PersistentPath)

	progmap := eb.GetMapByName("programs").(*goebpf.EbpfMap)
	ts.Require().NotNil(progmap)
	ts.NotEqual(0, progmap.GetFd())
	ts.Equal(goebpf.MapTypeProgArray, progmap.Type)
	ts.Equal(4, progmap.KeySize)
	ts.Equal(4, progmap.ValueSize)
	ts.Equal(2, progmap.MaxEntries)

	// Non existing map
	ts.Nil(eb.GetMapByName("something"))

	// Also there should few XDP eBPF programs recognized
	ts.Require().Equal(ts.programsCount, len(eb.GetPrograms()))

	// Check that everything loaded correctly / load program into kernel
	for name, program := range eb.GetPrograms() {
		// Check params
		ts.Equal(goebpf.ProgramTypeXdp, program.GetType())
		ts.Equal(name, program.GetName())
		ts.Equal("GPL", program.GetLicense())
		// Load into kernel
		err = program.Load()
		ts.Require().NoError(err)
		ts.Require().NotEqual(0, program.GetFd())
	}

	// Try to pin program into some filesystem
	xdp0 := eb.GetProgramByName("xdp0")
	path := bpfPath + "/xdp_pin_test"
	err = xdp0.Pin(path)
	ts.NoError(err)
	ts.FileExists(path)
	os.Remove(path)

	// Non existing program
	ts.Nil(eb.GetProgramByName("something"))

	// Additional test for special map type - PROGS_ARRAY
	// To be sure that we can insert prog_fd into map
	xdp1 := eb.GetProgramByName("xdp1")
	err = progmap.Update(0, xdp0.GetFd())
	ts.NoError(err)
	err = progmap.Update(1, xdp1.GetFd())
	ts.NoError(err)
	// And delete from it
	err = progmap.Delete(0)
	ts.NoError(err)
	err = progmap.Delete(1)
	ts.NoError(err)

	// Attach program to first (lo) interface
	// P.S. XDP does not work on "lo" interface, however, you can still attach program to it
	// which is enough to test basic BPF functionality
	err = xdp0.Attach("lo")
	ts.Require().NoError(err)
	err = xdp0.Detach()
	ts.NoError(err)

	// Attach with parameters
	err = xdp0.Attach(&goebpf.XdpAttachParams{
		Interface: "lo",
		Mode:      goebpf.XdpAttachModeSkb,
	})
	ts.Require().NoError(err)
	err = xdp0.Detach()
	ts.NoError(err)

	// "lo" interface does not support XDP natively, so should fail
	err = xdp0.Attach(&goebpf.XdpAttachParams{
		Interface: "lo",
		Mode:      goebpf.XdpAttachModeDrv,
	})
	ts.Require().Error(err)

	// Unload programs (not required for real use case)
	for _, program := range eb.GetPrograms() {
		err = program.Close()
		ts.NoError(err)
	}

	// Negative: close already closed program
	err = xdp0.Close()
	ts.Error(err)

	// Negative: attach to non existing interface
	err = xdp0.Attach("dummyiface")
	ts.Error(err)
}

func (ts *xdpTestSuite) TestProgramInfo() {
	// Load test program, don't attach (not required to get info)
	eb := goebpf.NewDefaultEbpfSystem()
	err := eb.LoadElf(ts.programFilename)
	ts.Require().NoError(err)
	prog := eb.GetProgramByName("xdp0")
	err = prog.Load()
	ts.Require().NoError(err)

	// Get program info by FD (NOT ID, since this program is ours)
	info, err := goebpf.GetProgramInfoByFd(prog.GetFd())
	ts.NoError(err)

	// Check base info
	ts.Equal(prog.GetName(), info.Name)
	ts.Equal(prog.GetFd(), info.Fd)
	ts.Equal(goebpf.ProgramTypeXdp, info.Type)
	ts.True(info.JitedProgramLen > 50)
	ts.True(info.XlatedProgramLen > 60)
	// Check loaded time
	now := time.Now()
	ts.True(now.Sub(info.LoadTime) < time.Second*10)

	// Check maps
	// xdp_prog1 uses only one map - array_map
	origMap := eb.GetMapByName("array_map").(*goebpf.EbpfMap)
	infoMap := info.Maps["array_map"].(*goebpf.EbpfMap)
	err = infoMap.Create()
	ts.NoError(err)
	// Check major fields (cannot compare one to one since at least fd different)
	ts.Equal(origMap.Name, infoMap.Name)
	ts.Equal(origMap.Type, infoMap.Type)
	ts.Equal(origMap.KeySize, infoMap.KeySize)
	ts.Equal(origMap.ValueSize, infoMap.ValueSize)
	ts.Equal(origMap.MaxEntries, infoMap.MaxEntries)
	// Ensure that infoMap mirrors origMap
	err = origMap.Update(0, 123)
	ts.NoError(err)
	val, err := infoMap.LookupInt(0)
	ts.NoError(err)
	ts.Equal(123, val)
}

// Run suite
func TestXdpSuite(t *testing.T) {
	suite.Run(t, &xdpTestSuite{
		programFilename: xdpProgramFilename,
		programsCount:   5,
		mapsCount:       7,
	})
}
