package check

import "testing"

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Severity
		wantErr bool
	}{
		{name: "low", input: "low", want: SeverityLow},
		{name: "medium", input: "medium", want: SeverityMedium},
		{name: "high", input: "high", want: SeverityHigh},
		{name: "critical", input: "critical", want: SeverityCritical},
		{name: "case insensitive", input: "HiGh", want: SeverityHigh},
		{name: "trims space", input: " critical ", want: SeverityCritical},
		{name: "unknown name", input: "severe", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSeverity(tt.input)

			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseSeverity(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSeverityStringRoundTrips(t *testing.T) {
	for _, s := range []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		got, err := ParseSeverity(s.String())

		if err != nil || got != s {
			t.Errorf("ParseSeverity(%q) = %v, %v; want %v", s.String(), got, err, s)
		}
	}
}

func TestSeverityOrder(t *testing.T) {
	if !(SeverityLow < SeverityMedium && SeverityMedium < SeverityHigh && SeverityHigh < SeverityCritical) {
		t.Error("severities must order low < medium < high < critical for --fail-on comparisons")
	}
}

func TestSeverityStringInvalid(t *testing.T) {
	if got := Severity(0).String(); got != "Severity(0)" {
		t.Errorf("Severity(0).String() = %q, want %q", got, "Severity(0)")
	}
}
