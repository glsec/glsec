package version

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		want    Version
		wantErr bool
	}{
		{"16.0", Version{16, 0}, false},
		{"15.7", Version{15, 7}, false},
		{"16", Version{16, 0}, false},
		{"", Version{}, false},
		{"abc", Version{}, true},
		{"16.x", Version{}, true},
		{"0.1", Version{}, true},
		{"-1.0", Version{}, true},
	}
	for _, tc := range cases {
		got, err := Parse(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("Parse(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("Parse(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestAtLeast(t *testing.T) {
	cases := []struct {
		v, other Version
		want     bool
	}{
		{Version{16, 0}, Version{15, 7}, true},
		{Version{15, 7}, Version{15, 7}, true},
		{Version{15, 6}, Version{15, 7}, false},
		{Version{14, 9}, Version{15, 0}, false},
		{Version{17, 0}, Version{16, 11}, true},
	}
	for _, tc := range cases {
		got := tc.v.AtLeast(tc.other)
		if got != tc.want {
			t.Errorf("%v.AtLeast(%v) = %v, want %v", tc.v, tc.other, got, tc.want)
		}
	}
}

func TestIsZero(t *testing.T) {
	zero := Version{}
	if !zero.IsZero() {
		t.Error("zero value should be zero")
	}
	if (Version{15, 0}).IsZero() {
		t.Error("15.0 should not be zero")
	}
}
