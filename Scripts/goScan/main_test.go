package main

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		spec string
		want []int
		err  bool
	}{
		{"80,443", []int{80, 443}, false},
		{"1-3", []int{1, 2, 3}, false},
		{"443,1-3,443", []int{1, 2, 3, 443}, false}, // dedup + sort
		{"3-1", []int{1, 2, 3}, false},              // reversed range
		{"0", nil, true},
		{"70000", nil, true},
		{"1-70000", nil, true},
		{"abc", nil, true},
	}
	for _, c := range cases {
		got, err := parsePorts(c.spec)
		if c.err {
			if err == nil {
				t.Errorf("parsePorts(%q): expected error", c.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePorts(%q): unexpected error %v", c.spec, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parsePorts(%q) = %v, want %v", c.spec, got, c.want)
		}
	}
}

func TestParsePortsTopDefault(t *testing.T) {
	got, err := parsePorts("top")
	if err != nil || len(got) == 0 {
		t.Fatalf("top ports failed: %v", err)
	}
	empty, _ := parsePorts("")
	if !reflect.DeepEqual(got, empty) {
		t.Errorf("empty spec should equal 'top'")
	}
}

func TestExpandTargetsSingleAndRange(t *testing.T) {
	got, err := expandTargets("10.0.0.1-10.0.0.3")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.3"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("range expand = %v, want %v", got, want)
	}
}

func TestExpandTargetsCIDR(t *testing.T) {
	got, err := expandTargets("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 { // /30 -> 4 addresses
		t.Errorf("/30 expanded to %d addrs, want 4", len(got))
	}
}

func TestExpandTargetsDedup(t *testing.T) {
	got, err := expandTargets("10.0.0.1, 10.0.0.1, 10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("dedup failed: got %d, want 2", len(got))
	}
}

func TestExpandTargetsErrors(t *testing.T) {
	for _, bad := range []string{"", "not-an-ip", "999.1.1.1", "10.0.0.0/99"} {
		if _, err := expandTargets(bad); err == nil {
			t.Errorf("expandTargets(%q): expected error", bad)
		}
	}
}
