package main

import (
	"testing"
)

func TestSet09(t *testing.T) {
	expect := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	got := padBlock([]byte("YELLOW SUBMARINE"), 20)
	if len(got) != len(expect) {
		t.Errorf("wrong size, expecting %d and got %d", 20, len(got))
	}

	if string(got) != string(expect) {
		t.Errorf("wrong bytes")
	}
}
