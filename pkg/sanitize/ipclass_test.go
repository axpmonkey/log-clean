package sanitize

import (
	"path/filepath"
	"testing"
)

const ipClassLog = "conn from 10.1.2.3 to 8.8.8.8 via 192.168.5.6, loopback 127.0.0.1, peer 10.1.2.3\n"

// P2: --ip-class keeps the private/public distinction ("is this traffic
// leaving the network?") while still hiding the address.
func TestIPClassTokens(t *testing.T) {
	in := t.TempDir()
	writeTestFile(t, in, "net.log", ipClassLog)

	out := filepath.Join(t.TempDir(), "out")
	result, err := Sanitize(Options{InputDir: in, OutputDir: out, AuditEnabled: true, IPClass: true})
	if err != nil {
		t.Fatal(err)
	}
	got := readOut(t, filepath.Join(out, "net.log"))
	want := "conn from IPV4_PRIV_001 to IPV4_PUB_001 via IPV4_PRIV_002, loopback IPV4_PRIV_003, peer IPV4_PRIV_001\n"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if len(result.AuditFindings) != 0 {
		t.Errorf("audit flags the class tokens: %+v", result.AuditFindings)
	}
	back, err := Reverse(result.MappingPath, got)
	if err != nil {
		t.Fatal(err)
	}
	if back != ipClassLog {
		t.Errorf("reverse = %q, want %q", back, ipClassLog)
	}

	// Off by default: plain IPV4_NNN.
	out2 := filepath.Join(t.TempDir(), "out")
	if _, err := Sanitize(Options{InputDir: in, OutputDir: out2}); err != nil {
		t.Fatal(err)
	}
	if got := readOut(t, filepath.Join(out2, "net.log")); got != "conn from IPV4_001 to IPV4_002 via IPV4_003, loopback IPV4_004, peer IPV4_001\n" {
		t.Errorf("default output changed: %q", got)
	}
}
