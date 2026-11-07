package iplore

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type column struct {
	Kind    string
	Scale   float64
	Vocab   string
	Flags   string
	Link    string
	Section int
}

type table struct {
	Keys    *int
	Columns map[string]column
}

type section struct {
	Encoding string
	Block    int
	Lzma     [3]uint
	Offsets  []int
	Firsts   []string
	Family   int
}

type field struct {
	Name string
	Path []string
}

type header struct {
	Dictionary   int
	Fields       []field
	Vocabularies map[string][]string
	Tables       map[string]table
	Sections     []section
}

type key struct{ high, low uint64 }

type block struct {
	ints    []uint32
	keys    []key
	strings []string
}

type node struct {
	parent      int
	section     int
	hostSection int
	column      column
	vocabulary  []string
}

type plan struct {
	spine, hosts int
	links        []node
	leaves       map[string]node
}

type Reader struct {
	bytes     []byte
	dataStart int
	header    header
	firsts    [][]key
	plans     [2]plan
	mutex     sync.Mutex
	cache     map[[2]int]block
}

var wanted = []string{
	"place.country.code",
	"network.asn",
	"network.operator.category",
	"abuse.risk",
	"abuse.service",
	"abuse.provider",
}

func Open(path string) (*Reader, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return newReader(bytes)
}

func newReader(bytes []byte) (*Reader, error) {
	if len(bytes) < 12 || string(bytes[:8]) != "IPLORE\x00\x01" {
		return nil, errors.New("not an iplore v1 file")
	}
	length := uint64(binary.LittleEndian.Uint32(bytes[8:12]))
	if length > uint64(len(bytes)-12) {
		return nil, errors.New("truncated header")
	}
	raw, err := decompress(bytes[12:12+length], 3, 0, 0)
	if err != nil {
		return nil, err
	}
	reader := &Reader{bytes: bytes, dataStart: 12 + int(length)}
	reader.cache = map[[2]int]block{}
	if err := json.Unmarshal(raw, &reader.header); err != nil {
		return nil, err
	}
	if err := reader.prepare(); err != nil {
		return nil, err
	}
	return reader, nil
}

func (r *Reader) prepare() error {
	dataSize := len(r.bytes) - r.dataStart
	for index, spec := range r.header.Sections {
		if err := spec.validate(dataSize); err != nil {
			return fmt.Errorf("section %d: %w", index, err)
		}
		firsts, err := spec.parseFirsts()
		if err != nil {
			return fmt.Errorf("section %d: %w", index, err)
		}
		r.firsts = append(r.firsts, firsts)
	}
	r.plans = [2]plan{r.header.plan(4), r.header.plan(6)}
	for _, spec := range r.plans {
		if err := r.header.validatePlan(spec); err != nil {
			return err
		}
	}
	return nil
}

func (s section) validate(dataSize int) error {
	blocks := len(s.Offsets) - 1
	switch {
	case blocks < 0:
		return errors.New("no offsets")
	case s.Block < 1 || s.Block > maxOutput:
		return errors.New("invalid block size")
	case s.Lzma[0] > 8 || s.Lzma[1] > 4 || s.Lzma[2] > 4:
		return errors.New("invalid lzma properties")
	case s.Offsets[0] < 0 || s.Offsets[blocks] > dataSize:
		return errors.New("offsets outside the file")
	case s.Encoding != "ints" && s.Encoding != "keys" && s.Encoding != "strings":
		return errors.New("unknown encoding")
	}
	for index := 1; index <= blocks; index++ {
		if s.Offsets[index] <= s.Offsets[index-1] {
			return errors.New("offsets not increasing")
		}
	}
	return nil
}

func (s section) parseFirsts() ([]key, error) {
	if s.Encoding != "keys" {
		return nil, nil
	}
	if len(s.Firsts) != len(s.Offsets)-1 || s.Family != 4 && s.Family != 6 {
		return nil, errors.New("invalid key section")
	}
	firsts := make([]key, len(s.Firsts))
	for index, text := range s.Firsts {
		first, err := parseKey(text)
		if err != nil || index > 0 && first.less(firsts[index-1]) {
			return nil, errors.New("invalid first key")
		}
		firsts[index] = first
	}
	return firsts, nil
}

func (h *header) hasSection(index int, encoding string) bool {
	return index >= 0 && index < len(h.Sections) && h.Sections[index].Encoding == encoding
}

func (h *header) validatePlan(spec plan) error {
	for _, section := range []int{spec.spine, spec.hosts} {
		if section >= 0 && !h.hasSection(section, "keys") {
			return errors.New("key table without key section")
		}
	}
	steps := append(slices.Clone(spec.links), slices.Collect(maps.Values(spec.leaves))...)
	for _, step := range steps {
		if !h.hasSection(step.section, "ints") ||
			step.hostSection >= 0 && !h.hasSection(step.hostSection, "ints") ||
			step.column.Kind == "string" && !h.hasSection(len(h.Sections)-1, "strings") {
			return errors.New("column without matching section")
		}
	}
	return nil
}

func parseKey(text string) (key, error) {
	number, valid := new(big.Int).SetString(text, 10)
	if !valid || number.Sign() < 0 || number.BitLen() > 128 {
		return key{}, errors.New("invalid key")
	}
	mask := new(big.Int).SetUint64(^uint64(0))
	high := new(big.Int).Rsh(number, 64)
	return key{high.Uint64(), new(big.Int).And(number, mask).Uint64()}, nil
}

func (k key) less(other key) bool {
	return k.high < other.high || k.high == other.high && k.low < other.low
}

func (h *header) plan(family int) plan {
	suffix := string(rune('0' + family))
	keys := func(name string) int {
		spec, found := h.Tables[name+suffix]
		if !found || spec.Keys == nil {
			return -1
		}
		return *spec.Keys
	}
	result := plan{spine: keys("spine"), hosts: keys("hosts"), leaves: map[string]node{}}
	nodes := map[string]int{}
	for _, spec := range h.Fields {
		if !contains(wanted, spec.Name) || len(spec.Path) == 0 {
			continue
		}
		links, last := spec.Path[:len(spec.Path)-1], spec.Path[len(spec.Path)-1]
		parent, usable := -1, true
		for depth := range links {
			path := strings.Join(links[:depth+1], "|")
			index, known := nodes[path]
			if !known {
				step, found := h.node(links[depth], suffix, parent)
				if !found {
					usable = false
					break
				}
				index = len(result.links)
				nodes[path] = index
				result.links = append(result.links, step)
			}
			parent = index
		}
		if step, found := h.node(last, suffix, parent); usable && found {
			result.leaves[spec.Name] = step
		}
	}
	return result
}

func (h *header) node(step, suffix string, parent int) (node, bool) {
	tableName, columnName, _ := strings.Cut(step, ".")
	isSpine := tableName == "spine"
	if isSpine {
		tableName += suffix
	}
	spec, found := h.Tables[tableName].Columns[columnName]
	if !found {
		return node{}, false
	}
	result := node{parent, spec.Section, -1, spec, nil}
	hosts := h.Tables["hosts"+suffix].Columns
	if hostColumn, found := hosts[columnName]; isSpine && found {
		result.hostSection = hostColumn.Section
	}
	result.vocabulary = h.Vocabularies[spec.Vocab]
	return result, true
}

func (r *Reader) block(sectionIndex, blockIndex int, encoding string) (block, error) {
	if !r.header.hasSection(sectionIndex, encoding) {
		return block{}, errors.New("section mismatch")
	}
	spec := r.header.Sections[sectionIndex]
	if blockIndex < 0 || blockIndex >= len(spec.Offsets)-1 {
		return block{}, errors.New("row outside the section")
	}
	r.mutex.Lock()
	defer r.mutex.Unlock()
	identity := [2]int{sectionIndex, blockIndex}
	if cached, found := r.cache[identity]; found {
		return cached, nil
	}
	start := r.dataStart + spec.Offsets[blockIndex]
	end := r.dataStart + spec.Offsets[blockIndex+1]
	raw, err := decompress(r.bytes[start:end], spec.Lzma[0], spec.Lzma[1], spec.Lzma[2])
	if err != nil {
		return block{}, err
	}
	var decoded block
	switch encoding {
	case "ints":
		decoded.ints, err = decodeInts(raw)
	case "keys":
		first := r.firsts[sectionIndex][blockIndex]
		decoded.keys, err = decodeKeys(raw, first, spec.Family)
	default:
		decoded.strings, err = decodeStrings(raw)
	}
	if err != nil {
		return block{}, err
	}
	r.cache[identity] = decoded
	return decoded, nil
}

var errTruncated = errors.New("truncated block")

func varint(bytes []byte, position *int) (uint64, error) {
	var value uint64
	for shift := 0; shift < 64; shift += 7 {
		if *position >= len(bytes) {
			return 0, errTruncated
		}
		next := bytes[*position]
		*position++
		value |= uint64(next&0x7f) << shift
		if next < 0x80 {
			return value, nil
		}
	}
	return 0, errors.New("varint too long")
}

func unzigzag(value uint64) int64 {
	return int64(value>>1) ^ -int64(value&1)
}

func decodeInts(raw []byte) ([]uint32, error) {
	if len(raw) == 0 {
		return nil, errTruncated
	}
	width, delta := int(raw[0]&0x7f), raw[0]&0x80 != 0
	if width < 1 || width > 8 || (len(raw)-1)%width != 0 {
		return nil, errors.New("invalid integer width")
	}
	var previous uint64
	values := make([]uint32, 0, (len(raw)-1)/width)
	for start := 1; start < len(raw); start += width {
		var padded [8]byte
		copy(padded[:], raw[start:start+width])
		value := binary.LittleEndian.Uint64(padded[:])
		if delta {
			previous += uint64(unzigzag(value))
		} else {
			previous = value
		}
		values = append(values, uint32(previous))
	}
	return values, nil
}

func decodeKeys(raw []byte, first key, family int) ([]key, error) {
	var keys []key
	position, previous := 0, first
	for position < len(raw) {
		gap, err := varint(raw, &position)
		if err != nil {
			return nil, err
		}
		if family != 6 {
			previous.low += gap
		} else {
			low, err := varint(raw, &position)
			if err != nil {
				return nil, err
			}
			if gap == 0 {
				low += previous.low
			}
			previous = key{previous.high + gap, low}
		}
		keys = append(keys, previous)
	}
	return keys, nil
}

func decodeStrings(raw []byte) ([]string, error) {
	var pool []string
	var previous []byte
	for position := 0; position < len(raw); {
		shared, err := varint(raw, &position)
		if err != nil {
			return nil, err
		}
		length, err := varint(raw, &position)
		if err != nil {
			return nil, err
		}
		if shared > uint64(len(previous)) || length > uint64(len(raw)-position) {
			return nil, errTruncated
		}
		previous = append(previous[:shared], raw[position:position+int(length)]...)
		position += int(length)
		pool = append(pool, string(previous))
	}
	return pool, nil
}

func (r *Reader) find(sectionIndex int, address key, exact bool) (int, error) {
	if sectionIndex < 0 {
		return -1, nil
	}
	firsts := r.firsts[sectionIndex]
	blockIndex := sort.Search(len(firsts), func(i int) bool {
		return address.less(firsts[i])
	})
	if blockIndex == 0 {
		return -1, nil
	}
	blockIndex--
	decoded, err := r.block(sectionIndex, blockIndex, "keys")
	if err != nil {
		return -1, err
	}
	keys := decoded.keys
	index := sort.Search(len(keys), func(i int) bool { return address.less(keys[i]) })
	if index == 0 || exact && keys[index-1] != address {
		return -1, nil
	}
	return blockIndex*r.header.Sections[sectionIndex].Block + index - 1, nil
}

func (r *Reader) integer(sectionIndex, row int) (uint64, error) {
	if row < 0 || sectionIndex < 0 || sectionIndex >= len(r.header.Sections) {
		return 0, errors.New("row outside the section")
	}
	size := r.header.Sections[sectionIndex].Block
	decoded, err := r.block(sectionIndex, row/size, "ints")
	if err != nil {
		return 0, err
	}
	if row%size >= len(decoded.ints) {
		return 0, errors.New("row outside the block")
	}
	return uint64(decoded.ints[row%size]), nil
}

func (r *Reader) text(index uint64) (string, error) {
	last := len(r.header.Sections) - 1
	if index >= 1<<32 || last < 0 {
		return "", errors.New("string outside the pool")
	}
	size := r.header.Sections[last].Block
	decoded, err := r.block(last, int(index)/size, "strings")
	if err != nil {
		return "", err
	}
	if int(index)%size >= len(decoded.strings) {
		return "", errors.New("string outside the block")
	}
	return decoded.strings[int(index)%size], nil
}

func (r *Reader) decode(step node, value uint64) (any, error) {
	spec := step.column
	switch {
	case spec.Link != "":
		return nil, nil
	case spec.Vocab != "":
		if value < uint64(len(step.vocabulary)) {
			return step.vocabulary[value], nil
		}
		return nil, nil
	case spec.Kind == "string":
		return r.text(value)
	}
	number := float64(value)
	if spec.Kind == "signed" {
		number = float64(unzigzag(value))
	}
	if spec.Scale > 0 {
		number /= spec.Scale
	}
	return number, nil
}

func addressKey(address netip.Addr) key {
	if address.Is4() {
		return key{0, uint64(binary.BigEndian.Uint32(address.AsSlice()))}
	}
	bytes := address.As16()
	return key{binary.BigEndian.Uint64(bytes[:8]), binary.BigEndian.Uint64(bytes[8:])}
}

var ErrAddress = errors.New("invalid address")

func validPort(text string) bool {
	_, err := strconv.ParseUint(text, 10, 16)
	return err == nil
}

func parseHost(text string) netip.Addr {
	address, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Addr{}
	}
	return address.WithZone("").Unmap()
}

func parseBracketed(text string) netip.Addr {
	host, rest, found := strings.Cut(text[1:], "]")
	address := parseHost(host)
	if !found || !strings.Contains(host, ":") {
		return netip.Addr{}
	}
	if rest != "" && (rest[0] != ':' || !validPort(rest[1:])) {
		return netip.Addr{}
	}
	return address
}

func parseAddress(text string) netip.Addr {
	if strings.HasPrefix(text, "[") {
		return parseBracketed(text)
	}
	if strings.Count(text, ":") != 1 {
		return parseHost(text)
	}
	host, port, _ := strings.Cut(text, ":")
	if !validPort(port) {
		return netip.Addr{}
	}
	return parseHost(host)
}

func (r *Reader) Lookup(text string) (map[string]any, error) {
	address := parseAddress(text)
	if !address.IsValid() {
		return nil, ErrAddress
	}
	spec := r.plans[0]
	if address.Is6() {
		spec = r.plans[1]
	}
	target := addressKey(address)
	spine, err := r.find(spec.spine, target, false)
	if err != nil {
		return nil, err
	}
	host, err := r.find(spec.hosts, target, true)
	if err != nil {
		return nil, err
	}
	read := func(step node, rows []int) (uint64, bool, error) {
		row, hostRow := spine, host
		if step.parent >= 0 {
			row, hostRow = rows[step.parent], -1
		}
		section := step.section
		if step.hostSection >= 0 && hostRow >= 0 {
			row, section = hostRow, step.hostSection
		}
		if row < 0 {
			return 0, false, nil
		}
		value, err := r.integer(section, row)
		return value - 1, value > 0, err
	}
	rows := make([]int, 0, len(spec.links))
	for _, step := range spec.links {
		value, found, err := read(step, rows)
		if err != nil {
			return nil, err
		}
		rows = append(rows, pick(found, int(value), -1))
	}
	values := map[string]any{}
	for name, step := range spec.leaves {
		value, found, err := read(step, rows)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		if values[name], err = r.decode(step, value); err != nil {
			return nil, err
		}
	}
	return values, nil
}
