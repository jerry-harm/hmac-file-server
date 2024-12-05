package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
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

// Function to fetch system data
func fetchSystemData() (string, error) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return "", fmt.Errorf("failed to fetch memory data: %w", err)
	}

	c, err := cpu.Percent(0, false)
	if err != nil {
		return "", fmt.Errorf("failed to fetch CPU data: %w", err)
	}

	cores, err := cpu.Counts(true)
	if err != nil {
		return "", fmt.Errorf("failed to fetch CPU cores: %w", err)
	}

	return fmt.Sprintf("Memory Usage: %.2f%%\nCPU Usage: %.2f%%\nCPU Cores: %d", v.UsedPercent, c[0], cores), nil
}

// Function to update the UI with the latest metrics and system data
func updateUI(app *tview.Application, sysTextView, metricsTable *tview.TextView) {
	for {
		metrics, err := fetchMetrics()
		if err != nil {
			app.QueueUpdateDraw(func() {
				metricsTable.SetText(fmt.Sprintf("Error fetching metrics: %v", err))
			})
			time.Sleep(5 * time.Second)
			continue
		}

		systemData, err := fetchSystemData()
		if err != nil {
			app.QueueUpdateDraw(func() {
				sysTextView.SetText(fmt.Sprintf("Error fetching system data: %v", err))
			})
			time.Sleep(5 * time.Second)
			continue
		}

		app.QueueUpdateDraw(func() {
			sysTextView.SetText(systemData)

			var output strings.Builder
			for key, value := range metrics {
				output.WriteString(fmt.Sprintf("%s: %s\n", key, value))
			}
			metricsTable.SetText(output.String())
		})

		time.Sleep(5 * time.Second)
	}
}

func main() {
	app := tview.NewApplication()

	// Create system data text view
	sysTextView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWrap(true).
		SetTextAlign(tview.AlignLeft).
		SetChangedFunc(func() {
			app.Draw()
		})

	// Create Prometheus metrics table
	metricsTable := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWrap(true).
		SetTextAlign(tview.AlignLeft).
		SetChangedFunc(func() {
			app.Draw()
		})

	// Create a flex layout to hold the system data and metrics
	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(sysTextView, 0, 1, false).
		AddItem(metricsTable, 0, 3, false)

	// Add key binding to exit the application
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyRune && event.Rune() == 'q' {
			app.Stop()
		}
		return event
	})

	// Start the UI update loop
	go updateUI(app, sysTextView, metricsTable)

	// Set the root and run the application
	if err := app.SetRoot(flex, true).Run(); err != nil {
		panic(err)
	}
}
