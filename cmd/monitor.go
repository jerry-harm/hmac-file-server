package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
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
func updateUI(app *tview.Application, table *tview.Table) {
	for {
		metrics, err := fetchMetrics()
		if err != nil {
			app.QueueUpdateDraw(func() {
				table.Clear()
				table.SetCell(0, 0, tview.NewTableCell(fmt.Sprintf("Error fetching metrics: %v", err)).SetTextColor(tcell.ColorRed))
			})
			time.Sleep(5 * time.Second)
			continue
		}

		app.QueueUpdateDraw(func() {
			table.Clear()
			row := 0
			for key, value := range metrics {
				table.SetCell(row, 0, tview.NewTableCell(key).SetTextColor(tcell.ColorYellow))
				table.SetCell(row, 1, tview.NewTableCell(value).SetTextColor(tcell.ColorWhite))
				row++
			}
		})

		time.Sleep(5 * time.Second)
	}
}

func main() {
	app := tview.NewApplication()
	table := tview.NewTable().
		SetBorders(false).
		SetFixed(1, 1)

	go updateUI(app, table)

	if err := app.SetRoot(table, true).Run(); err != nil {
		panic(err)
	}
}
