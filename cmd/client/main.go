package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
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

	defaultKeepAlive := false
	if v := os.Getenv("KEEP_ALIVE"); v == "true" || v == "1" {
		defaultKeepAlive = true
	}

	inputPath := flag.String("input", defaultInput, "Path to input JSON file")
	serverURL := flag.String("server", defaultServer, "Server base URL (e.g. http://localhost:8080)")
	keepAlive := flag.Bool("keep-alive", defaultKeepAlive, "Keep client alive after outputting results")
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

	// If keepAlive is requested, hang until SIGINT/SIGTERM
	if *keepAlive {
		fmt.Fprintln(os.Stderr, "\n[Client] Recognition completed successfully. Container is keeping alive...")
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		fmt.Fprintln(os.Stderr, "[Client] Received termination signal. Exiting.")
	}
}
