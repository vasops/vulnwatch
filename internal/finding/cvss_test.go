package finding

import "testing"

func TestCVSS3Score(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
		err    bool
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9, false},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, false},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H", 9.0, false},
		{"CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:H/I:N/A:N", 5.8, false},
		{"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.3, false},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, false},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 0, true},
		{"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got, err := CVSS3Score(tt.vector)
			if (err != nil) != tt.err {
				t.Fatalf("err = %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %v want %v", got, tt.want)
			}
		})
	}
}
