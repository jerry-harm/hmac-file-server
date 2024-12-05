package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/rivo/tview"
)

const prometheusURL = "http://localhost:9090/metrics"

// Function to fetch and parse Prometheus metrics
func fetchMetrics() (map[string]string, error) {
	resp, err := http.Get(prometheusURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metrics: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	metrics := make(map[string]string)
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "hmac_file_server_") || strings.HasPrefix(line, "memory_usage_bytes") || strings.HasPrefix(line, "cpu_usage_percent") || strings.HasPrefix(line, "active_connections_total") || strings.HasPrefix(line, "goroutines_count") {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				metrics[parts[0]] = parts[1]
			}
		}
	}

	return metrics, nil
}

// Function to update the UI with the latest metrics
func updateUI(app *tview.Application, textView *tview.TextView) {
	for {
		metrics, err := fetchMetrics()
		if err != nil {
			textView.SetText(fmt.Sprintf("Error fetching metrics: %v", err))
			time.Sleep(5 * time.Second)
			continue
		}

		var output strings.Builder
		output.WriteString("HMAC Server Metrics\n")
		output.WriteString("====================\n")
		for key, value := range metrics {
			output.WriteString(fmt.Sprintf("%s: %s\n", key, value))
		}

		app.QueueUpdateDraw(func() {
			textView.SetText(output.String())
		})

		time.Sleep(5 * time.Second)
	}
}

func main() {
	app := tview.NewApplication()
	textView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWrap(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	go updateUI(app, textView)

	if err := app.SetRoot(textView, true).Run(); err != nil {
		panic(err)
	}
}
