package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/prometheus/common/expfmt"
	"github.com/rivo/tview"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

const prometheusURL = "http://localhost:9090/metrics"

// Function to fetch and parse Prometheus metrics
func fetchMetrics() (map[string]float64, error) {
	resp, err := http.Get(prometheusURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metrics: %w", err)
	}
	defer resp.Body.Close()

	parser := &expfmt.TextParser{} // Corrected initialization
	metricFamilies, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metrics: %w", err)
	}

	metrics := make(map[string]float64)
	for name, mf := range metricFamilies {
		// Filter the metrics you're interested in
		if strings.HasPrefix(name, "hmac_file_server_") ||
			name == "memory_usage_bytes" ||
			name == "cpu_usage_percent" ||
			name == "active_connections_total" ||
			name == "goroutines_count" {

			for _, m := range mf.GetMetric() {
				var value float64
				if m.GetGauge() != nil {
					value = m.GetGauge().GetValue()
				} else if m.GetCounter() != nil {
					value = m.GetCounter().GetValue()
				} else if m.GetUntyped() != nil {
					value = m.GetUntyped().GetValue()
				}

				// Handle metrics with labels
				if len(m.GetLabel()) > 0 {
					labels := make([]string, 0)
					for _, label := range m.GetLabel() {
						labels = append(labels, fmt.Sprintf("%s=\"%s\"", label.GetName(), label.GetValue()))
					}
					metricKey := fmt.Sprintf("%s{%s}", name, strings.Join(labels, ","))
					metrics[metricKey] = value
				} else {
					metrics[name] = value
				}
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

	cpuUsage := 0.0
	if len(c) > 0 {
		cpuUsage = c[0]
	}

	return fmt.Sprintf("Memory Usage: %.2f%%\nCPU Usage: %.2f%%\nCPU Cores: %d", v.UsedPercent, cpuUsage, cores), nil
}

// Function to update the UI with the latest metrics and system data
func updateUI(app *tview.Application, sysTextView, metricsTextView *tview.TextView) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		metrics, err := fetchMetrics()
		if err != nil {
			app.QueueUpdateDraw(func() {
				metricsTextView.SetText(fmt.Sprintf("Error fetching metrics: %v", err))
			})
			continue
		}

		systemData, err := fetchSystemData()
		if err != nil {
			app.QueueUpdateDraw(func() {
				sysTextView.SetText(fmt.Sprintf("Error fetching system data: %v", err))
			})
			continue
		}

		app.QueueUpdateDraw(func() {
			sysTextView.SetText(systemData)

			var output strings.Builder
			for key, value := range metrics {
				output.WriteString(fmt.Sprintf("%s: %.2f\n", key, value))
			}
			metricsTextView.SetText(output.String())
		})
	}
}

func main() {
	app := tview.NewApplication()

	// Create system data text view with border and title
	sysTextView := tview.NewTextView()
	sysTextView.SetDynamicColors(true)
	sysTextView.SetRegions(true)
	sysTextView.SetWrap(true)
	sysTextView.SetTextAlign(tview.AlignLeft)
	sysTextView.SetBorder(true)         // Separated method calls
	sysTextView.SetTitle("System Data") // Separated method calls

	// Create Prometheus metrics text view with border and title
	metricsTextView := tview.NewTextView()
	metricsTextView.SetDynamicColors(true)
	metricsTextView.SetRegions(true)
	metricsTextView.SetWrap(true)
	metricsTextView.SetTextAlign(tview.AlignLeft)
	metricsTextView.SetBorder(true)                // Separated method calls
	metricsTextView.SetTitle("Prometheus Metrics") // Separated method calls

	// Create a flex layout to hold the text views
	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(sysTextView, 0, 1, false).
		AddItem(metricsTextView, 0, 3, false)

	// Add key binding to exit the application
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyRune && (event.Rune() == 'q' || event.Rune() == 'Q') {
			app.Stop()
			return nil
		}
		return event
	})

	// Start the UI update loop
	go updateUI(app, sysTextView, metricsTextView)

	// Set the root and run the application
	if err := app.SetRoot(flex, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
