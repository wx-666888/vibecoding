package fingerprint

import (
	"testing"
)

func TestEngineIdentify(t *testing.T) {
	engine, err := LoadRules("")
	if err != nil {
		t.Fatalf("failed to load default rules: %v", err)
	}

	tests := []struct {
		name     string
		input    Input
		expected Result
	}{
		{
			name: "SSH OpenSSH Ubuntu",
			input: Input{
				IP:     "1.2.3.4",
				Port:   22,
				Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
			},
			expected: Result{
				Protocol: "SSH",
				Product:  "OpenSSH",
				Version:  "8.9p1",
				OSHint:   "Ubuntu",
			},
		},
		{
			name: "HTTP nginx",
			input: Input{
				IP:     "1.2.3.5",
				Port:   80,
				Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html",
			},
			expected: Result{
				Protocol: "HTTP",
				Product:  "nginx",
				Version:  "1.24.0",
				OSHint:   "",
			},
		},
		{
			name: "HTTP Apache",
			input: Input{
				IP:     "1.2.3.6",
				Port:   443,
				Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57",
			},
			expected: Result{
				Protocol: "HTTP",
				Product:  "Apache",
				Version:  "2.4.57",
				OSHint:   "",
			},
		},
		{
			name: "MySQL 8.0.32",
			input: Input{
				IP:     "1.2.3.7",
				Port:   3306,
				Banner: "J\x00\x00\x00\n8.0.32\x00",
			},
			expected: Result{
				Protocol: "MySQL",
				Product:  "MySQL",
				Version:  "8.0.32",
				OSHint:   "",
			},
		},
		{
			name: "MySQL 5.7.42 literal slash x",
			input: Input{
				IP:     "1.2.3.14",
				Port:   3306,
				Banner: `J\x00\x00\x00\n5.7.42\x00`,
			},
			expected: Result{
				Protocol: "MySQL",
				Product:  "MySQL",
				Version:  "5.7.42",
				OSHint:   "",
			},
		},
		{
			name: "Redis error",
			input: Input{
				IP:     "1.2.3.8",
				Port:   6379,
				Banner: "-ERR wrong number of arguments for 'get' command",
			},
			expected: Result{
				Protocol: "Redis",
				Product:  "Redis",
				Version:  "",
				OSHint:   "",
			},
		},
		{
			name: "Redis pong",
			input: Input{
				IP:     "1.2.3.15",
				Port:   6379,
				Banner: "+PONG",
			},
			expected: Result{
				Protocol: "Redis",
				Product:  "Redis",
				Version:  "",
				OSHint:   "",
			},
		},
		{
			name: "FTP ProFTPD",
			input: Input{
				IP:     "1.2.3.9",
				Port:   21,
				Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)",
			},
			expected: Result{
				Protocol: "FTP",
				Product:  "ProFTPD",
				Version:  "1.3.7",
				OSHint:   "",
			},
		},
		{
			name: "FTP vsFTPd",
			input: Input{
				IP:     "1.2.3.16",
				Port:   21,
				Banner: "220 (vsFTPd 3.0.5)",
			},
			expected: Result{
				Protocol: "FTP",
				Product:  "vsFTPd",
				Version:  "3.0.5",
				OSHint:   "",
			},
		},
		{
			name: "HTTP Jetty",
			input: Input{
				IP:     "1.2.3.10",
				Port:   8080,
				Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51",
			},
			expected: Result{
				Protocol: "HTTP",
				Product:  "Jetty",
				Version:  "9.4.51",
				OSHint:   "",
			},
		},
		{
			name: "HTTP IIS",
			input: Input{
				IP:     "1.2.3.20",
				Port:   8888,
				Banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0",
			},
			expected: Result{
				Protocol: "HTTP",
				Product:  "Microsoft-IIS",
				Version:  "10.0",
				OSHint:   "",
			},
		},
		{
			name: "SSH OpenSSH 4.3 SSH-1.99",
			input: Input{
				IP:     "1.2.3.18",
				Port:   22,
				Banner: "SSH-1.99-OpenSSH_4.3",
			},
			expected: Result{
				Protocol: "SSH",
				Product:  "OpenSSH",
				Version:  "4.3",
				OSHint:   "",
			},
		},
		{
			name: "Unknown banner",
			input: Input{
				IP:     "1.2.3.23",
				Port:   12345,
				Banner: "QUIT\r\n",
			},
			expected: Result{
				Protocol: "unknown",
				Product:  "",
				Version:  "",
				OSHint:   "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := engine.Identify(tt.input)
			if res.Protocol != tt.expected.Protocol {
				t.Errorf("Protocol mismatch: got %q, want %q", res.Protocol, tt.expected.Protocol)
			}
			if res.Product != tt.expected.Product {
				t.Errorf("Product mismatch: got %q, want %q", res.Product, tt.expected.Product)
			}
			if res.Version != tt.expected.Version {
				t.Errorf("Version mismatch: got %q, want %q", res.Version, tt.expected.Version)
			}
			if res.OSHint != tt.expected.OSHint {
				t.Errorf("OSHint mismatch: got %q, want %q", res.OSHint, tt.expected.OSHint)
			}
		})
	}
}
