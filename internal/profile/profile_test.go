package profile

import "testing"

func TestLoadBuiltinParsesAllProfiles(t *testing.T) {
	profiles, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	want := map[string]bool{
		"default": false, "sas94": false, "tomcat": false,
		"apache": false, "postgres-wipds": false, "activemq": false, "geode": false,
	}
	for _, p := range profiles {
		if _, ok := want[p.Name]; !ok {
			t.Errorf("unexpected profile %q", p.Name)
		}
		want[p.Name] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected builtin profile %q not loaded", name)
		}
	}
}

func TestDetectByFilename(t *testing.T) {
	profiles, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	cases := []struct {
		filename string
		want     string
	}{
		{"catalina.out", "tomcat"},
		{"access_log.2026-06-30", "apache"},
		{"sas.log", "sas94"},
		{"activemq.log", "activemq"},
		{"locator0view.log", "geode"},
		{"wipds-query.log", "postgres-wipds"},
		{"totally_unrelated_filename.txt", "default"},
	}
	for _, c := range cases {
		t.Run(c.filename, func(t *testing.T) {
			got := Detect(profiles, c.filename, "")
			if got.Name != c.want {
				t.Errorf("Detect(%q) = %q, want %q", c.filename, got.Name, c.want)
			}
		})
	}
}

func TestDetectByFirstLine(t *testing.T) {
	profiles, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	cases := []struct {
		name      string
		firstLine string
		want      string
	}{
		{"tomcat banner", "30-Jun-2026 12:00:00.123 INFO [main] org.apache.catalina.startup.Catalina.start", "tomcat"},
		{"apache common log", `192.168.1.1 - - [30/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1234`, "apache"},
		{"activemq line", "2026-06-30 12:00:00,123 | INFO | Apache ActiveMQ starting", "activemq"},
		{"geode line", "[info 2026/06/30 12:00:00.000 UTC] starting locator", "geode"},
		{"unrecognized", "this does not look like any known format", "default"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Detect(profiles, "ambiguous.log", c.firstLine)
			if got.Name != c.want {
				t.Errorf("Detect with first line %q = %q, want %q", c.firstLine, got.Name, c.want)
			}
		})
	}
}

func TestByName(t *testing.T) {
	profiles, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	p, ok := ByName(profiles, "sas94")
	if !ok || p.Name != "sas94" {
		t.Errorf("ByName(sas94) = %+v, %v", p, ok)
	}
	_, ok = ByName(profiles, "does-not-exist")
	if ok {
		t.Error("ByName found a profile that shouldn't exist")
	}
}

func TestDetectFallsBackToDefaultWithNoMatch(t *testing.T) {
	profiles, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}
	got := Detect(profiles, "mystery.dat", "no recognizable banner here")
	if got.Name != "default" {
		t.Errorf("Detect = %q, want default", got.Name)
	}
}
