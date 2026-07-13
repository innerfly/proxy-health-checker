package main

import (
	"bufio"
	"os"
	"strings"
)

func loadEnv(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentKey string
	var currentValue strings.Builder

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if line starts a new KEY=VALUE entry
		if key, value, ok := strings.Cut(line, "="); ok && !strings.ContainsAny(strings.TrimSpace(key), ":/?&") {
			// Save previous key-value if exists
			if currentKey != "" {
				os.Setenv(currentKey, currentValue.String())
			}

			// Parse new key-value
			currentKey = strings.TrimSpace(key)
			currentValue.Reset()
			currentValue.WriteString(strings.TrimSpace(value))
		} else {
			// Continuation line
			if currentKey != "" {
				if currentValue.Len() > 0 {
					currentValue.WriteString(",")
				}
				currentValue.WriteString(line)
			}
		}
	}

	// Save last key-value
	if currentKey != "" {
		os.Setenv(currentKey, currentValue.String())
	}

	return scanner.Err()
}
