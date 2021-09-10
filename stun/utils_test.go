package stun

import (
	"testing"
)

func TestPadding(t *testing.T) {
	b := []byte{1, 2}
	expected := []byte{1, 2, 0, 0}
	result := padding(b)
	if len(result) != len(expected) {
		t.Errorf("Padding error: result size wrong.\n")
	}
	for i := range expected {
		if expected[i] != result[i] {
			t.Errorf("Padding error: data wrong in bit %d.\n", i)
		}
	}
}

func TestAlign(t *testing.T) {
	d := make(map[uint16]uint16)
	d[1] = 4
	d[4] = 4
	d[5] = 8
	d[6] = 8
	d[7] = 8
	d[8] = 8
	d[65528] = 65528
	d[65529] = 65532
	d[65531] = 65532
	d[65532] = 65532
	for k, v := range d {
		if align(k) != v {
			t.Errorf("Align error: expected %d, get %d", align(k), v)
		}
	}
}
