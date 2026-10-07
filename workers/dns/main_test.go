package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestExcludedHostDoesNotResolve(t *testing.T) {
	var output bytes.Buffer
	input := `{"id":"fixture","hosts":["blocked.example.org"],"include":["*.example.org"],"exclude":["blocked.example.org"]}`
	if err := run(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	var result Result
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error == "" || len(result.Addresses) != 0 {
		t.Fatal("excluded host processed")
	}
}
func TestIPAndWildcard(t *testing.T) {
	job := Job{Include: []string{"*.example.org", "192.0.2.0/24"}}
	if allowed("example.org", job) || allowed("example.org.evil.org", job) {
		t.Fatal("suffix bypass")
	}
	if !allowed("a.example.org", job) || !allowed("192.0.2.4", job) {
		t.Fatal("valid scope rejected")
	}
	var output bytes.Buffer
	if err := run(strings.NewReader(`{"hosts":["192.0.2.4"],"include":["192.0.2.0/24"]}`), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "192.0.2.4") {
		t.Fatal("missing IP")
	}
}
func TestMalformedJob(t *testing.T) {
	if err := run(strings.NewReader(`{"hosts":[]}`), &bytes.Buffer{}); err == nil {
		t.Fatal("empty job accepted")
	}
}
