package detect

import "testing"

func TestIPv4Detector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"simple match", "Connected from 192.168.1.1", []string{"192.168.1.1"}},
		{"loopback matches", "bind to 127.0.0.1", []string{"127.0.0.1"}},
		{"private range matches", "server 10.0.0.5 up", []string{"10.0.0.5"}},
		{"two ips on one line", "10.0.0.1 talked to 10.0.0.2", []string{"10.0.0.1", "10.0.0.2"}},
		{"max octet values", "broadcast 255.255.255.255", []string{"255.255.255.255"}},

		{"version string with v prefix", "running v9.4.1.2 build", nil},
		{"version string with version keyword", "SAS version 9.4.1.2 installed", nil},
		{"version string with release keyword", "release 9.4.1.2 notes", nil},
		{"sas product version", "SAS 9.4.1.2 build", nil},
		{"out of range octet", "not an ip 999.1.1.1 here", nil},

		{"overlap edge: ip right after sas without space", "SAS9.4.1.2", nil},
		{"version keyword outside 20-char window still matches", "version banner from long ago, then 9.4.1.2 appears", []string{"9.4.1.2"}},
	}
	d := IPv4Detector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			expectSubstringMatches(t, matches, c.input, c.want, "IPV4")
		})
	}
}

func TestIPv6Detector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string // expected matched Value strings, in order
	}{
		{"full form", "addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 connected",
			[]string{"2001:0db8:85a3:0000:0000:8a2e:0370:7334"}},
		{"compressed form", "listening on fe80::1 now",
			[]string{"fe80::1"}},
		{"ipv4 mapped form", "client ::ffff:192.168.1.1 joined",
			[]string{"::ffff:192.168.1.1"}},
		{"with zone id", "fe80::1%eth0 link-local",
			[]string{"fe80::1%eth0"}},
		{"loopback", "bind to ::1 socket",
			[]string{"::1"}},

		{"sas timestamp not matched", "12:34:56.789 INFO starting", nil},
		{"single colon not matched", "ratio 4:3 aspect", nil},
		{"ipv4 address not matched as ipv6", "Connected from 192.168.1.1", nil},
		{"plain word not matched", "no addresses here", nil},
		{"port-like single colon not matched", "host:8080 listening", nil},
	}
	d := IPv6Detector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			if len(matches) != len(c.want) {
				t.Fatalf("got %d matches, want %d: %+v", len(matches), len(c.want), matches)
			}
			for i, m := range matches {
				if m.Value != c.want[i] {
					t.Errorf("match %d value = %q, want %q", i, m.Value, c.want[i])
				}
				if m.Category != "IPV6" {
					t.Errorf("match %d category = %q, want IPV6", i, m.Category)
				}
			}
		})
	}
}

func TestFQDNDetector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"internal fqdn", "connecting to db-prod-01.acme.internal now",
			[]string{"db-prod-01.acme.internal"}},
		{"public com fqdn", "fetched from api.example.com today",
			[]string{"api.example.com"}},
		{"corp pseudo-tld", "host app01.customer.corp reachable",
			[]string{"app01.customer.corp"}},
		{"multi-label fqdn", "node1.cluster.svc.lan registered",
			[]string{"node1.cluster.svc.lan"}},
		{"two fqdns one line", "from db-prod-01.acme.internal to app-prod-01.acme.internal",
			[]string{"db-prod-01.acme.internal", "app-prod-01.acme.internal"}},

		{"filename not fqdn", "wrote output to app.log", nil},
		{"xml filename not fqdn", "parsed server.xml config", nil},
		{"java class not fqdn", "at org.apache.foo.Bar.run(Bar.java:42)", nil},
		{"single label not fqdn", "running on localhost directly", nil},
		{"version-shaped not fqdn since no tld", "build 9.4.1.2 finished", nil},

		{"label too long rejected", "x" + repeat("a", 64) + ".com is too long", nil},
		{"case insensitive tld", "fetched from API.EXAMPLE.COM today", []string{"API.EXAMPLE.COM"}},

		{"jvm property catalina.home not fqdn", "-Dcatalina.home=/opt/tomcat", nil},
		{"jvm property java.net not fqdn", "-Djava.net.preferIPv4Stack=true", nil},
		{"jvm property com.sun not fqdn", "-Dcom.sun.management.jmxremote.port=1099", nil},
		{"jvm property com.sas.svcs not fqdn", "-Dcom.sas.svcs.info=enabled", nil},
		{"real hostname still caught without -D prefix", "Dcatalina.home is a literal hostname", []string{"Dcatalina.home"}},
	}
	d := FQDNDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			if len(matches) != len(c.want) {
				t.Fatalf("got %d matches, want %d: %+v", len(matches), len(c.want), matches)
			}
			for i, m := range matches {
				if m.Value != c.want[i] {
					t.Errorf("match %d value = %q, want %q", i, m.Value, c.want[i])
				}
				if m.Category != "HOST" {
					t.Errorf("match %d category = %q, want HOST", i, m.Category)
				}
			}
		})
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func TestMACDetector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"colon separated", "wlan0: 00:1A:2B:3C:4D:5E up", []string{"00:1A:2B:3C:4D:5E"}},
		{"hyphen separated", "eth0 mac 00-1a-2b-3c-4d-5e found", []string{"00-1a-2b-3c-4d-5e"}},
		{"lowercase hex", "iface ab:cd:ef:01:02:03 ready", []string{"ab:cd:ef:01:02:03"}},
		{"two macs one line", "00:1A:2B:3C:4D:5E talked to 11:22:33:44:55:66", []string{"00:1A:2B:3C:4D:5E", "11:22:33:44:55:66"}},
		{"mac at line start", "00:1A:2B:3C:4D:5E is the mac", []string{"00:1A:2B:3C:4D:5E"}},

		{"too few groups", "00:1A:2B:3C:4D not a mac", nil},
		{"non hex chars", "00:1A:2B:3C:4D:5G invalid", nil},
		{"plain text", "no hardware addresses here", nil},
		{"ipv4 not matched as mac", "Connected from 192.168.1.1", nil},
		{"uuid not matched as mac", "id=550e8400-e29b-41d4-a716-446655440000", nil},
	}
	d := MACDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			expectSubstringMatches(t, matches, c.input, c.want, "MAC")
		})
	}
}

func TestURLDetector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"https url", "fetched https://api.example.com/v1/data successfully",
			[]string{"https://api.example.com/v1/data"}},
		{"jdbc url", "connecting to jdbc:postgresql://db-prod-01:5432/sasdb now",
			[]string{"jdbc:postgresql://db-prod-01:5432/sasdb"}},
		{"ldap url", "bind to ldap://dc01.acme.internal:389 succeeded",
			[]string{"ldap://dc01.acme.internal:389"}},
		{"activemq tcp url", "broker at tcp://mq-prod-01:61616 connected",
			[]string{"tcp://mq-prod-01:61616"}},
		{"url stops at quote", `url="https://api.example.com/v1" returned 200`,
			[]string{"https://api.example.com/v1"}},

		{"plain text no url", "nothing to see here", nil},
		{"bare host no scheme", "db-prod-01.acme.internal is up", nil},
		{"unsupported scheme not matched", "file:///etc/passwd opened", nil},
		{"url stops at angle bracket", "<https://api.example.com/v1>", []string{"https://api.example.com/v1"}},
		{"url stops at comma", "see https://api.example.com/v1, for details", []string{"https://api.example.com/v1"}},
	}
	d := URLDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			if len(matches) != len(c.want) {
				t.Fatalf("got %d matches, want %d: %+v", len(matches), len(c.want), matches)
			}
			for i, m := range matches {
				if m.Value != c.want[i] {
					t.Errorf("match %d value = %q, want %q", i, m.Value, c.want[i])
				}
				if m.Category != "URL" {
					t.Errorf("match %d category = %q, want URL", i, m.Category)
				}
			}
		})
	}
}

func TestEmbeddedHost(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantHost string
		wantOK   bool
	}{
		{"host and port", "https://db-prod-01.acme.internal:5432/path", "db-prod-01.acme.internal", true},
		{"host with credentials", "https://jdoe:secret@db-prod-01.acme.internal/path", "db-prod-01.acme.internal", true},
		{"host with no port or path", "tcp://mq-prod-01", "mq-prod-01", true},
		{"no scheme separator", "db-prod-01.acme.internal", "", false},
		{"host with query string", "https://api.example.com?key=1", "api.example.com", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, ok := EmbeddedHost(c.input)
			if ok != c.wantOK || host != c.wantHost {
				t.Errorf("EmbeddedHost(%q) = (%q, %v), want (%q, %v)", c.input, host, ok, c.wantHost, c.wantOK)
			}
		})
	}
}
