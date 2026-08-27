package main

import "testing"

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{"bare host", "example.com", "example.com", "443", false},
		{"host and port", "example.com:8443", "example.com", "8443", false},
		{"https url with path", "https://example.com/a/b?c=d", "example.com", "443", false},
		{"https url with port", "https://example.com:9000/x", "example.com", "9000", false},
		{"http url defaults to 443", "http://example.com", "example.com", "443", false},
		{"ipv6 with port", "[2606:4700::1111]:443", "2606:4700::1111", "443", false},
		{"ipv6 bare", "2606:4700::1111", "2606:4700::1111", "443", false},
		{"surrounding whitespace", "  example.com  ", "example.com", "443", false},
		{"empty", "", "", "", true},
		{"port only", ":443", "", "", true},
		{"non-numeric port", "example.com:https", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := parseTarget(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseTarget(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if host != tt.wantHost || port != tt.wantPort {
				t.Fatalf("parseTarget(%q) = %q, %q; want %q, %q", tt.in, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}
