package iplore

import "errors"

var maxOutput = 1 << 24

var errCorruptStream = errors.New("corrupt lzma stream")

type lengthCoder struct {
	choice []uint16
	low    []uint16
	mid    []uint16
	high   []uint16
}

type decoder struct {
	input    []byte
	position int
	rng      uint32
	code     uint32
}

func newProbabilities(count int) []uint16 {
	probabilities := make([]uint16, count)
	for index := range probabilities {
		probabilities[index] = 1024
	}
	return probabilities
}

func newLengthCoder() *lengthCoder {
	return &lengthCoder{
		choice: newProbabilities(2),
		low:    newProbabilities(16 * 8),
		mid:    newProbabilities(16 * 8),
		high:   newProbabilities(256),
	}
}

func pick(condition bool, yes, no int) int {
	if condition {
		return yes
	}
	return no
}

func (d *decoder) normalize() {
	if d.rng >= 1<<24 {
		return
	}
	d.rng <<= 8
	d.code = d.code<<8 | uint32(d.input[d.position])
	d.position++
}

func (d *decoder) bit(probability *uint16) int {
	d.normalize()
	bound := (d.rng >> 11) * uint32(*probability)
	if d.code < bound {
		d.rng = bound
		*probability += (2048 - *probability) >> 5
		return 0
	}
	d.rng -= bound
	d.code -= bound
	*probability -= *probability >> 5
	return 1
}

func (d *decoder) direct(count int) uint32 {
	var value uint32
	for ; count > 0; count-- {
		d.normalize()
		d.rng >>= 1
		value <<= 1
		if d.code >= d.rng {
			d.code -= d.rng
			value |= 1
		}
	}
	return value
}

func (d *decoder) tree(probabilities []uint16, count int) int {
	node := 1
	for index := 0; index < count; index++ {
		node = node<<1 | d.bit(&probabilities[node])
	}
	return node - 1<<count
}

func (d *decoder) reverse(probabilities []uint16, count int) uint32 {
	node, value := 1, uint32(0)
	for index := 0; index < count; index++ {
		bit := d.bit(&probabilities[node])
		node = node<<1 | bit
		value |= uint32(bit) << index
	}
	return value
}

func (d *decoder) length(coder *lengthCoder, posState int) int {
	if d.bit(&coder.choice[0]) == 0 {
		return d.tree(coder.low[posState*8:], 3)
	}
	if d.bit(&coder.choice[1]) == 0 {
		return 8 + d.tree(coder.mid[posState*8:], 3)
	}
	return 16 + d.tree(coder.high, 8)
}

func decompress(input []byte, lc, lp, pb uint) (output []byte, err error) {
	if lc > 8 || lp > 4 || pb > 4 || len(input) < 5 {
		return nil, errCorruptStream
	}
	defer func() {
		if recover() != nil {
			output, err = nil, errCorruptStream
		}
	}()
	d := &decoder{input: input, rng: 0xFFFFFFFF}
	for ; d.position < 5; d.position++ {
		d.code = d.code<<8 | uint32(input[d.position])
	}
	output = make([]byte, 0, min(len(input)*4, maxOutput))
	literal := newProbabilities(0x300 << (lc + lp))
	isMatch := newProbabilities(12 << 4)
	isRep0Long := newProbabilities(12 << 4)
	isRep := newProbabilities(12)
	isRepG0 := newProbabilities(12)
	isRepG1 := newProbabilities(12)
	isRepG2 := newProbabilities(12)
	special := newProbabilities(115)
	align := newProbabilities(16)
	var slots [4][]uint16
	for index := range slots {
		slots[index] = newProbabilities(64)
	}
	matchLength, repLength := newLengthCoder(), newLengthCoder()
	state, rep0, rep1, rep2, rep3 := 0, 0, 0, 0, 0
	for {
		if len(output) > maxOutput {
			return nil, errCorruptStream
		}
		posState := len(output) & (1<<pb - 1)
		if d.bit(&isMatch[state<<4+posState]) == 0 {
			var previous int
			if len(output) > 0 {
				previous = int(output[len(output)-1])
			}
			context := (len(output)&(1<<lp-1))<<lc + previous>>(8-lc)
			probabilities := literal[0x300*context:]
			symbol := 1
			if state >= 7 {
				matched := int(output[len(output)-rep0-1])
				for symbol < 0x100 {
					matchBit := matched >> 7 & 1
					matched <<= 1
					bit := d.bit(&probabilities[(1+matchBit)<<8+symbol])
					symbol = symbol<<1 | bit
					if matchBit != bit {
						break
					}
				}
			}
			for symbol < 0x100 {
				symbol = symbol<<1 | d.bit(&probabilities[symbol])
			}
			output = append(output, byte(symbol))
			state = literalState(state)
			continue
		}
		var size int
		if d.bit(&isRep[state]) == 0 {
			rep3, rep2, rep1 = rep2, rep1, rep0
			size = d.length(matchLength, posState)
			state = pick(state < 7, 7, 10)
			rep0 = int(d.distance(slots[pick(size < 3, size, 3)], special, align))
			if rep0 == 0xFFFFFFFF {
				return output, nil
			}
		} else {
			if d.bit(&isRepG0[state]) == 0 {
				if d.bit(&isRep0Long[state<<4+posState]) == 0 {
					state = pick(state < 7, 9, 11)
					output = append(output, output[len(output)-rep0-1])
					continue
				}
			} else {
				distance := rep1
				if d.bit(&isRepG1[state]) == 1 {
					distance = rep2
					if d.bit(&isRepG2[state]) == 1 {
						distance, rep3 = rep3, rep2
					}
					rep2 = rep1
				}
				rep1, rep0 = rep0, distance
			}
			size = d.length(repLength, posState)
			state = pick(state < 7, 8, 11)
		}
		for index := 0; index < size+2; index++ {
			output = append(output, output[len(output)-rep0-1])
		}
	}
}

func literalState(state int) int {
	if state < 4 {
		return 0
	}
	if state < 10 {
		return state - 3
	}
	return state - 6
}

func (d *decoder) distance(slotProbabilities, special, align []uint16) uint32 {
	slot := d.tree(slotProbabilities, 6)
	if slot < 4 {
		return uint32(slot)
	}
	count := slot>>1 - 1
	distance := uint32(2|slot&1) << count
	if slot < 14 {
		return distance + d.reverse(special[int(distance)-slot:], count)
	}
	distance += d.direct(count-4) << 4
	return distance + d.reverse(align, 4)
}
