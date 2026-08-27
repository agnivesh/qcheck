package main

import "testing"

func TestParseResolve(t *testing.T) {
	tests := []struct {
		name               string
		in                 string
		wantHost, wantPort string
		wantAddr           string
		wantErr            bool
	}{
		{"ipv4", "example.com:443:1.2.3.4", "example.com", "443", "1.2.3.4", false},
		{"custom port", "example.com:8443:10.0.0.1", "example.com", "8443", "10.0.0.1", false},
		{"ipv6 bracketed", "example.com:443:[2606:4700::1111]", "example.com", "443", "2606:4700::1111", false},
		{"ipv6 bare", "example.com:443:::1", "example.com", "443", "::1", false},
		{"missing addr", "example.com:443", "", "", "", true},
		{"non-numeric port", "example.com:https:1.2.3.4", "", "", "", true},
		{"not an ip", "example.com:443:not-an-ip", "", "", "", true},
		{"empty", "", "", "", "", true},
		{"leading colon", ":443:1.2.3.4", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, addr, err := parseResolve(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseResolve(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if host != tt.wantHost || port != tt.wantPort || addr != tt.wantAddr {
				t.Fatalf("parseResolve(%q) = %q,%q,%q; want %q,%q,%q",
					tt.in, host, port, addr, tt.wantHost, tt.wantPort, tt.wantAddr)
			}
		})
	}
}

func TestResolveFlagSet(t *testing.T) {
	var f resolveFlag
	if err := f.Set("example.com:443:1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if err := f.Set("api.example.com:8443:5.6.7.8"); err != nil {
		t.Fatal(err)
	}
	if got := f.overrides["example.com:443"]; got != "1.2.3.4:443" {
		t.Errorf("override = %q, want 1.2.3.4:443", got)
	}
	if got := f.overrides["api.example.com:8443"]; got != "5.6.7.8:8443" {
		t.Errorf("override = %q, want 5.6.7.8:8443", got)
	}
}
