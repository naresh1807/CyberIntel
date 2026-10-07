// cyberrecon-dns: one bounded NDJSON job on stdin, one result per host on stdout.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

type Job struct {
	ID          string   `json:"id"`
	Hosts       []string `json:"hosts"`
	Include     []string `json:"include"`
	Exclude     []string `json:"exclude"`
	Concurrency int      `json:"concurrency"`
}
type Result struct {
	ID        string   `json:"id"`
	Host      string   `json:"host"`
	Addresses []string `json:"addresses"`
	Error     string   `json:"error,omitempty"`
}

func matches(host, pattern string) bool {
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:]) && host != pattern[2:]
	}
	if prefix, err := netip.ParsePrefix(pattern); err == nil {
		ip, err := netip.ParseAddr(host)
		return err == nil && prefix.Contains(ip)
	}
	return host == pattern
}
func allowed(host string, job Job) bool {
	for _, rule := range job.Exclude {
		if matches(host, rule) {
			return false
		}
	}
	for _, rule := range job.Include {
		if matches(host, rule) {
			return true
		}
	}
	return false
}
func validHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if len(host) > 253 || host != strings.ToLower(host) {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}
func run(input io.Reader, output io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(input, 1024*1024+1))
	if err != nil {
		return err
	}
	if len(raw) > 1024*1024 {
		return fmt.Errorf("input exceeds 1 MiB")
	}
	var job Job
	if err := json.Unmarshal(raw, &job); err != nil {
		return err
	}
	if len(job.Hosts) == 0 || len(job.Hosts) > 30 || len(job.Include) == 0 || len(job.Include)+len(job.Exclude) > 2048 {
		return fmt.Errorf("invalid job bounds")
	}
	for _, rule := range job.Include {
		if rule == "0.0.0.0/0" || rule == "::/0" {
			return fmt.Errorf("internet-wide scope prohibited")
		}
	}
	if job.Concurrency < 1 || job.Concurrency > 8 {
		job.Concurrency = 4
	}
	tasks := make(chan string)
	var workers sync.WaitGroup
	var mutex sync.Mutex
	encoder := json.NewEncoder(output)
	var writeErr error
	for index := 0; index < job.Concurrency; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for host := range tasks {
				result := Result{ID: job.ID, Host: host, Addresses: []string{}}
				if !validHost(host) || !allowed(host, job) {
					result.Error = "OUT OF SCOPE or invalid host"
				} else if ip, err := netip.ParseAddr(host); err == nil {
					result.Addresses = append(result.Addresses, ip.String())
				} else {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host+".")
					cancel()
					if err != nil {
						result.Error = "DNS resolution failed"
					} else {
						seen := map[string]bool{}
						for _, address := range addresses {
							value := address.IP.String()
							if !seen[value] && len(result.Addresses) < 100 {
								result.Addresses = append(result.Addresses, value)
								seen[value] = true
							}
						}
					}
				}
				mutex.Lock()
				if err := encoder.Encode(result); err != nil && writeErr == nil {
					writeErr = err
				}
				mutex.Unlock()
			}
		}()
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for index, host := range job.Hosts {
		if index > 0 {
			<-ticker.C
		}
		tasks <- host
	}
	close(tasks)
	workers.Wait()
	return writeErr
}
func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
