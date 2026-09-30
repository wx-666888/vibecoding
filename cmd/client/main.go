package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	defaultInput := os.Getenv("INPUT_FILE")
	if defaultInput == "" {
		defaultInput = "examples/input.json"
	}

	defaultServer := os.Getenv("SERVER_URL")
	if defaultServer == "" {
		defaultServer = "http://localhost:8080"
	}

	inputPath := flag.String("input", defaultInput, "Path to input JSON file")
	serverURL := flag.String("server", defaultServer, "Server base URL (e.g. http://localhost:8080)")
	flag.Parse()

	// Read input file
	data, err := os.ReadFile(*inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to read input file %q: %v\n", *inputPath, err)
		os.Exit(1)
	}

	// Clean server URL
	baseURL := strings.TrimRight(*serverURL, "/")
	targetURL := baseURL + "/fingerprint"

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Post(targetURL, "application/json", bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to connect to server at %s: %v\n", targetURL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to read server response: %v\n", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Error: server returned HTTP %d: %s\n", resp.StatusCode, string(respBody))
		os.Exit(1)
	}

	// Pretty-print JSON to stdout
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, respBody, "", "  "); err != nil {
		// Fallback to raw output if indentation fails
		fmt.Println(string(respBody))
	} else {
		fmt.Println(prettyJSON.String())
	}
}
