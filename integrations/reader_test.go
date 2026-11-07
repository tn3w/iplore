package iplore

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func randomAddresses(count int) []string {
	random := rand.New(rand.NewSource(7))
	addresses := []string{"1.1.1.1", "8.8.8.8", "185.220.101.1", "66.249.66.1"}
	addresses = append(addresses, "2606:4700:4700::1111", "10.0.0.1", "::ffff:1.1.1.1")
	for len(addresses) < count {
		if len(addresses)%4 != 0 {
			octets := [4]byte{}
			random.Read(octets[:])
			addresses = append(addresses, netip.AddrFrom4(octets).String())
			continue
		}
		octets := [16]byte{0x20 | byte(random.Intn(16))}
		random.Read(octets[1:])
		addresses = append(addresses, netip.AddrFrom16(octets).String())
	}
	return addresses
}

func nativeValue(tree map[string]any, name string) any {
	var current any = tree
	for _, step := range strings.Split(name, ".") {
		object, isObject := current.(map[string]any)
		if !isObject {
			return nil
		}
		current = object[step]
	}
	return current
}

func TestMatchesNativeReader(t *testing.T) {
	binary, database := os.Getenv("IPLORE_BIN"), os.Getenv("IPLORE_DB")
	if binary == "" || database == "" {
		t.Skip("IPLORE_BIN and IPLORE_DB not set")
	}
	reader, err := Open(database)
	if err != nil {
		t.Fatal(err)
	}
	populated := 0
	for _, address := range randomAddresses(200) {
		output, err := exec.Command(binary, database, address).Output()
		if err != nil {
			t.Fatalf("%s: %v", address, err)
		}
		var native map[string]any
		if err := json.Unmarshal(output, &native); err != nil {
			t.Fatal(err)
		}
		values, err := reader.Lookup(address)
		if err != nil {
			t.Fatalf("%s: %v", address, err)
		}
		for _, name := range wanted {
			expected := nativeValue(native, name)
			if !reflect.DeepEqual(values[name], expected) {
				t.Errorf("%s %s: got %v, want %v", address, name, values[name], expected)
			}
			if expected != nil {
				populated++
			}
		}
	}
	fmt.Printf("compared 200 addresses, %d populated values\n", populated)
}

const twoPow128 = "340282366920938463463374607431768211456"

func within(t *testing.T, action func()) {
	t.Helper()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		action()
	}()
	select {
	case recovered := <-done:
		if recovered != nil {
			t.Fatalf("panic: %v", recovered)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timed out")
	}
}

func smallDatabase(t *testing.T) []byte {
	t.Helper()
	content, err := os.ReadFile(databasePath(t, "iplore-country.ipl"))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestReleaseDatabasesOpen(t *testing.T) {
	names := []string{"country", "place", "network", "abuse", "anonymizer", "traffic"}
	names = append(names, "full")
	for _, name := range names {
		path := filepath.Join("../bindings/data", "iplore-"+name+".ipl")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		reader, err := Open(path)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, address := range randomAddresses(50) {
			if _, err := reader.Lookup(address); err != nil {
				t.Errorf("%s %s: %v", name, address, err)
			}
		}
	}
}

func TestTruncatedDatabaseIsRejected(t *testing.T) {
	content := smallDatabase(t)
	cuts := []int{0, 1, 8, 11, 12, 13, 100, 7000, 7251, 7252, 7253, len(content) / 2}
	cuts = append(cuts, len(content)-1000, len(content)-2, len(content)-1)
	for _, cut := range cuts {
		within(t, func() {
			if _, err := newReader(content[:cut]); err == nil {
				t.Errorf("accepted file cut at %d of %d", cut, len(content))
			}
		})
	}
}

func TestHugeHeaderLengthIsRejected(t *testing.T) {
	content := append([]byte{}, smallDatabase(t)...)
	copy(content[8:12], []byte{0xff, 0xff, 0xff, 0xff})
	if _, err := newReader(content); err == nil {
		t.Error("accepted header length beyond the file")
	}
}

func TestMutatedDatabaseNeverPanics(t *testing.T) {
	content := smallDatabase(t)
	random := rand.New(rand.NewSource(11))
	addresses := randomAddresses(20)
	within(t, func() {
		for round := 0; round < 150; round++ {
			mutated := append([]byte{}, content...)
			for range 1 + random.Intn(8) {
				mutated[random.Intn(len(mutated))] = byte(random.Intn(256))
			}
			reader, err := newReader(mutated)
			if err != nil {
				continue
			}
			for _, address := range addresses {
				reader.Lookup(address)
			}
		}
	})
}

func TestCorruptBlocksSurfaceErrors(t *testing.T) {
	content := smallDatabase(t)
	reader, err := newReader(content)
	if err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewSource(5))
	failures := 0
	within(t, func() {
		for range 200 {
			mutated := append([]byte{}, content...)
			step := 40 + random.Intn(200)
			for index := reader.dataStart; index < len(mutated); index += step {
				mutated[index] = byte(random.Intn(256))
			}
			broken, err := newReader(mutated)
			if err != nil {
				continue
			}
			for _, address := range randomAddresses(40) {
				if _, err := broken.Lookup(address); err != nil {
					failures++
				}
			}
		}
	})
	if failures == 0 {
		t.Error("corrupt blocks never produced a lookup error")
	}
}

func TestInvalidHeadersAreRejected(t *testing.T) {
	content := smallDatabase(t)
	cases := []struct {
		name   string
		mutate func(*header)
	}{
		{"zero block size", func(h *header) { h.Sections[0].Block = 0 }},
		{"negative block size", func(h *header) { h.Sections[0].Block = -5 }},
		{"huge block size", func(h *header) { h.Sections[0].Block = 1 << 40 }},
		{"no offsets", func(h *header) { h.Sections[0].Offsets = nil }},
		{"decreasing offsets", func(h *header) { h.Sections[2].Offsets[3] = 1 }},
		{"equal offsets", func(h *header) { h.Sections[2].Offsets[3] = 0 }},
		{"negative offset", func(h *header) { h.Sections[0].Offsets[0] = -1 }},
		{"offset past file", func(h *header) { h.Sections[6].Offsets[1] = 1 << 40 }},
		{"lc too large", func(h *header) { h.Sections[0].Lzma[0] = 9 }},
		{"lp too large", func(h *header) { h.Sections[0].Lzma[1] = 5 }},
		{"pb too large", func(h *header) { h.Sections[0].Lzma[2] = 5 }},
		{"unknown encoding", func(h *header) { h.Sections[0].Encoding = "floats" }},
		{"missing firsts", func(h *header) { h.Sections[2].Firsts = nil }},
		{"garbage first", func(h *header) { h.Sections[2].Firsts[1] = "x" }},
		{"negative first", func(h *header) { h.Sections[2].Firsts[1] = "-1" }},
		{"oversized first", func(h *header) { h.Sections[2].Firsts[1] = twoPow128 }},
		{"unsorted firsts", func(h *header) { h.Sections[2].Firsts[2] = "0" }},
		{"unknown family", func(h *header) { h.Sections[2].Family = 5 }},
		{"spine on ints", func(h *header) { *h.Tables["spine4"].Keys = 0 }},
		{"spine out of range", func(h *header) { *h.Tables["spine4"].Keys = 99 }},
		{"column out of range", func(h *header) { setSection(h, "spine4", "place", 99) }},
		{"column negative", func(h *header) { setSection(h, "spine4", "place", -1) }},
		{"column on keys", func(h *header) { setSection(h, "spine4", "place", 2) }},
		{"string without pool", func(h *header) { h.Sections[6].Encoding = "ints" }},
		{"leaf out of range", func(h *header) { setSection(h, "country", "code", 40) }},
	}
	for _, c := range cases {
		within(t, func() {
			reader, err := newReader(content)
			if err != nil {
				t.Fatal(err)
			}
			c.mutate(&reader.header)
			reader.firsts, reader.plans = nil, [2]plan{}
			if err := reader.prepare(); err == nil {
				t.Errorf("%s: accepted", c.name)
			}
		})
	}
}

func setSection(h *header, tableName, columnName string, index int) {
	spec := h.Tables[tableName].Columns[columnName]
	spec.Section = index
	h.Tables[tableName].Columns[columnName] = spec
}

func TestFieldWithoutPathIsIgnored(t *testing.T) {
	reader, err := newReader(smallDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	reader.header.Fields = []field{{Name: "place.country.code"}}
	reader.firsts = nil
	within(t, func() {
		if err := reader.prepare(); err != nil {
			t.Fatal(err)
		}
		if values, err := reader.Lookup("1.1.1.1"); err != nil || len(values) != 0 {
			t.Errorf("got %v %v", values, err)
		}
	})
}

func failed[T any](_ T, err error) bool {
	return err != nil
}

func TestRowsOutsideSectionsAreErrors(t *testing.T) {
	reader, err := newReader(smallDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	within(t, func() {
		for name, rejected := range map[string]bool{
			"row beyond blocks": failed(reader.integer(1, 1<<30)),
			"negative row":      failed(reader.integer(1, -1)),
			"unknown section":   failed(reader.integer(99, 0)),
			"negative section":  failed(reader.integer(-1, 0)),
			"keys as ints":      failed(reader.integer(2, 0)),
			"string beyond":     failed(reader.text(1 << 30)),
			"string in block":   failed(reader.text(16383)),
			"ints as keys":      failed(reader.block(0, 0, "keys")),
			"negative block":    failed(reader.block(0, -1, "ints")),
		} {
			if !rejected {
				t.Errorf("%s: no error", name)
			}
		}
	})
}

func TestDecodersRejectMalformedBlocks(t *testing.T) {
	within(t, func() {
		for name, rejected := range map[string]bool{
			"empty ints":       failed(decodeInts(nil)),
			"zero width":       failed(decodeInts([]byte{0, 1, 2})),
			"zero width delta": failed(decodeInts([]byte{0x80, 1})),
			"width above 8":    failed(decodeInts([]byte{9, 1, 2, 3})),
			"misaligned ints":  failed(decodeInts([]byte{2, 1, 2, 3})),
			"truncated varint": failed(decodeKeys([]byte{0x80}, key{}, 4)),
			"truncated low":    failed(decodeKeys([]byte{1}, key{}, 6)),
			"endless varint":   failed(decodeKeys(endless(), key{}, 4)),
			"shared too long":  failed(decodeStrings([]byte{3, 1, 'a'})),
			"length too long":  failed(decodeStrings([]byte{0, 9, 'a'})),
			"huge length":      failed(decodeStrings(append(endless()[:9], 1))),
			"missing size":     failed(decodeStrings([]byte{0})),
		} {
			if !rejected {
				t.Errorf("%s: no error", name)
			}
		}
	})
	values, err := decodeInts([]byte{2, 1, 0, 2, 0})
	if err != nil || len(values) != 2 || values[1] != 2 {
		t.Errorf("valid ints: %v %v", values, err)
	}
}

func endless() []byte {
	return []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

func TestDecompressRejectsBadInput(t *testing.T) {
	random := rand.New(rand.NewSource(3))
	bad := [][]byte{nil, {0}, {0, 0, 0, 0}, make([]byte, 5), make([]byte, 100)}
	for range 300 {
		garbage := make([]byte, 5+random.Intn(300))
		random.Read(garbage)
		bad = append(bad, garbage)
	}
	within(t, func() {
		for _, input := range bad {
			output, _ := decompress(input, 3, 0, 2)
			if len(output) > maxOutput+300 {
				t.Errorf("output of %d bytes", len(output))
			}
		}
	})
	for _, p := range [][3]uint{{9, 0, 0}, {0, 5, 0}, {0, 0, 5}} {
		_, err := decompress(make([]byte, 64), p[0], p[1], p[2])
		if err == nil {
			t.Errorf("accepted properties %v", p)
		}
	}
}

func TestDecompressedSizeIsCapped(t *testing.T) {
	content := smallDatabase(t)
	defer func(limit int) { maxOutput = limit }(maxOutput)
	maxOutput = 200
	if _, err := newReader(content); err == nil {
		t.Error("header larger than the output cap accepted")
	}
	maxOutput = 1 << 24
	reader, err := newReader(content)
	if err != nil {
		t.Fatal(err)
	}
	maxOutput = 200
	if _, err := reader.Lookup("1.1.1.1"); err == nil {
		t.Error("block larger than the output cap accepted")
	}
}
