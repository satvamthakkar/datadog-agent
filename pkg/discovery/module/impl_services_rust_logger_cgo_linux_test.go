// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025-present Datadog, Inc.

//go:build linux_bpf && cgo

package module

/*
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
*/
import "C"

import (
	"math"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// These tests exercise the cgo entry point goDiscoveryLogCallback directly
// with synthetic C buffers, covering the input-validation guards that cannot
// be reached from the pure-Go dispatch path.

func TestGoDiscoveryLogCallback_NilPointerIsNoOp(t *testing.T) {
	buf, flush := installCapturingLogger(t, log.TraceLvl)
	require.NotPanics(t, func() {
		goDiscoveryLogCallback(3, nil, 5) // nil ptr with non-zero len
	})
	flush()
	assert.Empty(t, buf.String(), "nil pointer must not produce a log record")
}

func TestGoDiscoveryLogCallback_ZeroLengthIsNoOp(t *testing.T) {
	buf, flush := installCapturingLogger(t, log.TraceLvl)
	cstr := C.CString("hello")
	defer C.free(unsafe.Pointer(cstr))

	require.NotPanics(t, func() {
		goDiscoveryLogCallback(3, cstr, 0)
	})
	flush()
	assert.Empty(t, buf.String(), "msgLen==0 must not produce a log record")
}

func TestGoDiscoveryLogCallback_LengthOverflowIsNoOp(t *testing.T) {
	buf, flush := installCapturingLogger(t, log.TraceLvl)
	cstr := C.CString("hello")
	defer C.free(unsafe.Pointer(cstr))

	// math.MaxInt32+1 would wrap when cast to C.int. The guard rejects it.
	require.NotPanics(t, func() {
		goDiscoveryLogCallback(3, cstr, C.size_t(math.MaxInt32)+1)
	})
	flush()
	assert.Empty(t, buf.String(), "oversize msgLen must not produce a log record")
}

func TestGoDiscoveryLogCallback_HappyPath(t *testing.T) {
	buf, flush := installCapturingLogger(t, log.TraceLvl)
	msg := "hello from rust"
	cstr := C.CString(msg)
	defer C.free(unsafe.Pointer(cstr))

	goDiscoveryLogCallback(3, cstr, C.size_t(len(msg)))
	flush()

	out := buf.String()
	assert.Contains(t, out, "[INFO]")
	assert.Contains(t, out, "[dd_discovery] "+msg)
}

// TestGoDiscoveryLogCallback_HonoursExplicitLength passes a length shorter
// than the NUL-terminated buffer's strlen to confirm the callback uses
// msgLen rather than treating the input as a C string. Rust passes
// non-NUL-terminated buffers, so this is the production-relevant path.
func TestGoDiscoveryLogCallback_HonoursExplicitLength(t *testing.T) {
	buf, flush := installCapturingLogger(t, log.TraceLvl)
	cstr := C.CString("hello world")
	defer C.free(unsafe.Pointer(cstr))

	goDiscoveryLogCallback(3, cstr, 5) // truncate to "hello"
	flush()

	out := buf.String()
	assert.Contains(t, out, "[dd_discovery] hello")
	assert.NotContains(t, out, "world", "msgLen must override the buffer's NUL terminator")
}

func TestGoDiscoveryLogCallback_AppliesGoSideLevelGate(t *testing.T) {
	// Logger configured at Info: a Debug-level cgo callback must drop
	// before reaching the underlying logger.
	buf, flush := installCapturingLogger(t, log.InfoLvl)
	msg := "debug record from rust"
	cstr := C.CString(msg)
	defer C.free(unsafe.Pointer(cstr))

	goDiscoveryLogCallback(4, cstr, C.size_t(len(msg))) // 4 = Debug
	flush()

	assert.Empty(t, buf.String(), "debug record must be filtered when logger is at info")
}
