package main

import (
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/prometheus/common/expfmt"
	"github.com/rivo/tview"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
)

const prometheusURL = "http://localhost:9090/metrics"

// Thresholds for color coding
const (
	HighUsage   = 80.0
	MediumUsage = 50.0
)

// ProcessInfo holds information about a process
type ProcessInfo struct {
	PID         int32
	Name        string
	CPUPercent  float64
	MemPercent  float32
	CommandLine string
}

// Function to fetch and parse Prometheus metrics
func fetchMetrics() (map[string]float64, error) {
	resp, err := http.Get(prometheusURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metrics: %w", err)
	}
	defer resp.Body.Close()

	parser := &expfmt.TextParser{}
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
				} else {
					// If the metric type is not handled, skip it
					continue
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
func fetchSystemData() (float64, float64, int, error) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to fetch memory data: %w", err)
	}

	c, err := cpu.Percent(0, false)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to fetch CPU data: %w", err)
	}

	cores, err := cpu.Counts(true)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to fetch CPU cores: %w", err)
	}

	cpuUsage := 0.0
	if len(c) > 0 {
		cpuUsage = c[0]
	}

	return v.UsedPercent, cpuUsage, cores, nil
}

// Function to fetch process list
func fetchProcessList() ([]ProcessInfo, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch processes: %w", err)
	}

	var processList []ProcessInfo

	for _, p := range processes {
		cpuPercent, err := p.CPUPercent()
		if err != nil {
			continue
		}

		memPercent, err := p.MemoryPercent()
		if err != nil {
			continue
		}

		name, err := p.Name()
		if err != nil {
			continue
		}

		cmdline, err := p.Cmdline()
		if err != nil {
			cmdline = ""
		}

		processList = append(processList, ProcessInfo{
			PID:         p.Pid,
			Name:        name,
			CPUPercent:  cpuPercent,
			MemPercent:  memPercent,
			CommandLine: cmdline,
		})
	}

	return processList, nil
}

// Function to update the UI with the latest data
func updateUI(app *tview.Application, sysTable, metricsTable, processTable *tview.Table) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Fetch system data
		memUsage, cpuUsage, cores, err := fetchSystemData()
		if err != nil {
			log.Printf("Error fetching system data: %v\n", err)
			continue
		}

		// Fetch metrics data
		metrics, err := fetchMetrics()
		if err != nil {
			log.Printf("Error fetching metrics: %v\n", err)
			continue
		}

		// Fetch process list
		processes, err := fetchProcessList()
		if err != nil {
			log.Printf("Error fetching process list: %v\n", err)
			continue
		}

		// Update the UI
		app.QueueUpdateDraw(func() {
			// Update system data table
			sysTable.Clear()
			sysTable.SetCell(0, 0, tview.NewTableCell("Metric").SetAttributes(tcell.AttrBold))
			sysTable.SetCell(0, 1, tview.NewTableCell("Value").SetAttributes(tcell.AttrBold))

			// CPU Usage Row
			cpuUsageCell := tview.NewTableCell(fmt.Sprintf("%.2f%%", cpuUsage))
			if cpuUsage > HighUsage {
				cpuUsageCell.SetTextColor(tcell.ColorRed)
			} else if cpuUsage > MediumUsage {
				cpuUsageCell.SetTextColor(tcell.ColorYellow)
			} else {
				cpuUsageCell.SetTextColor(tcell.ColorGreen)
			}
			sysTable.SetCell(1, 0, tview.NewTableCell("CPU Usage"))
			sysTable.SetCell(1, 1, cpuUsageCell)

			// Memory Usage Row
			memUsageCell := tview.NewTableCell(fmt.Sprintf("%.2f%%", memUsage))
			if memUsage > HighUsage {
				memUsageCell.SetTextColor(tcell.ColorRed)
			} else if memUsage > MediumUsage {
				memUsageCell.SetTextColor(tcell.ColorYellow)
			} else {
				memUsageCell.SetTextColor(tcell.ColorGreen)
			}
			sysTable.SetCell(2, 0, tview.NewTableCell("Memory Usage"))
			sysTable.SetCell(2, 1, memUsageCell)

			// CPU Cores Row
			sysTable.SetCell(3, 0, tview.NewTableCell("CPU Cores"))
			sysTable.SetCell(3, 1, tview.NewTableCell(fmt.Sprintf("%d", cores)))

			// Update metrics table
			metricsTable.Clear()
			metricsTable.SetCell(0, 0, tview.NewTableCell("Metric").SetAttributes(tcell.AttrBold))
			metricsTable.SetCell(0, 1, tview.NewTableCell("Value").SetAttributes(tcell.AttrBold))

			row := 1
			for key, value := range metrics {
				metricsTable.SetCell(row, 0, tview.NewTableCell(key))
				metricsTable.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%.2f", value)))
				row++
			}

			// Update process table
			processTable.Clear()
			processTable.SetCell(0, 0, tview.NewTableCell("PID").SetAttributes(tcell.AttrBold))
			processTable.SetCell(0, 1, tview.NewTableCell("Name").SetAttributes(tcell.AttrBold))
			processTable.SetCell(0, 2, tview.NewTableCell("CPU%").SetAttributes(tcell.AttrBold))
			processTable.SetCell(0, 3, tview.NewTableCell("Mem%").SetAttributes(tcell.AttrBold))
			processTable.SetCell(0, 4, tview.NewTableCell("Command").SetAttributes(tcell.AttrBold))

			// Sort processes by CPU usage
			sort.Slice(processes, func(i, j int) bool {
				return processes[i].CPUPercent > processes[j].CPUPercent
			})

			// Limit to top 20 processes
			maxRows := 20
			if len(processes) < maxRows {
				maxRows = len(processes)
			}

			for i := 0; i < maxRows; i++ {
				p := processes[i]
				processTable.SetCell(i+1, 0, tview.NewTableCell(fmt.Sprintf("%d", p.PID)))
				processTable.SetCell(i+1, 1, tview.NewTableCell(p.Name))
				processTable.SetCell(i+1, 2, tview.NewTableCell(fmt.Sprintf("%.2f", p.CPUPercent)))
				processTable.SetCell(i+1, 3, tview.NewTableCell(fmt.Sprintf("%.2f", p.MemPercent)))
				processTable.SetCell(i+1, 4, tview.NewTableCell(p.CommandLine))
			}
		})
	}
}

func main() {
	app := tview.NewApplication()

	// Create system data table
	sysTable := tview.NewTable().SetBorders(false)
	sysTable.SetTitle(" [::b]System Data ").SetBorder(true)

	// Create Prometheus metrics table
	metricsTable := tview.NewTable().SetBorders(false)
	metricsTable.SetTitle(" [::b]Prometheus Metrics ").SetBorder(true)

	// Create process list table
	processTable := tview.NewTable().SetBorders(false)
	processTable.SetTitle(" [::b]Process List ").SetBorder(true)

	// Create a flex layout to hold the tables
	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(sysTable, 7, 0, false).     // Fixed height for system data
		AddItem(metricsTable, 0, 1, false). // Proportional height for metrics
		AddItem(processTable, 0, 2, false)  // Proportional height for process list

	// Add key binding to exit the application
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyRune && (event.Rune() == 'q' || event.Rune() == 'Q') {
			app.Stop()
			return nil
		}
		return event
	})

	// Start the UI update loop in a separate goroutine
	go updateUI(app, sysTable, metricsTable, processTable)

	// Set the root and run the application
	if err := app.SetRoot(flex, true).EnableMouse(true).Run(); err != nil {
		log.Fatalf("Error running application: %v", err)
	}
}
