package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"context"
	"io"
	"sync"
	"bufio"

	"github.com/gdamore/tcell/v2"
	"github.com/pelletier/go-toml"
	"github.com/prometheus/common/expfmt"
	"github.com/rivo/tview"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
)

var (
	prometheusURL   string
	configFilePath  string // Pfad der gefundenen Konfiguration
	logFilePath     string // Pfad der Logdatei aus der Konfiguration
	metricsEnabled  bool   // Neue Variable für die Aktivierung von Metriken
	bindIP          string // Neue Variable für die gebundene IP-Adresse
)

func init() {
	configPaths := []string{
		"/etc/hmac-file-server/config.toml",
		"../config.toml",
		"./config.toml",
	}

	var config *toml.Tree
	var err error

	// Lade die config.toml aus den definierten Pfaden
	for _, path := range configPaths {
		config, err = toml.LoadFile(path)
		if err == nil {
			configFilePath = path
			log.Printf("Using config file: %s", configFilePath)
			break
		}
	}

	if err != nil {
		log.Fatalf("Error loading config file: %v\nPlease create a config.toml in one of the following locations:\n%v", err, configPaths)
	}

	// Metricsport auslesen
	portValue := config.Get("server.metricsport")
	if portValue == nil {
		log.Println("Warning: 'server.metricsport' is missing in the configuration, using default port 9090")
		portValue = int64(9090)
	}

	var port int64
	switch v := portValue.(type) {
	case int64:
		port = v
	case string:
		parsedPort, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			log.Fatalf("Error parsing 'server.metricsport' as int64: %v", err)
		}
		port = parsedPort
	default:
		log.Fatalf("Error: 'server.metricsport' is not of type int64 or string, got %T", v)
	}

	// Lesen von 'metricsenabled' aus der Konfiguration
	metricsEnabledValue := config.Get("server.metricsenabled")
	if metricsEnabledValue == nil {
		log.Println("Warning: 'server.metricsenabled' ist in der Konfiguration nicht gesetzt. Standardmäßig deaktiviert.")
		metricsEnabled = false
	} else {
		var ok bool
		metricsEnabled, ok = metricsEnabledValue.(bool)
		if !ok {
			log.Fatalf("Konfigurationsfehler: 'server.metricsenabled' sollte ein boolescher Wert sein, aber %T wurde gefunden.", metricsEnabledValue)
		}
	}

	// Lesen von 'bind_ip' aus der Konfiguration
	bindIPValue := config.Get("server.bind_ip")
	if bindIPValue == nil {
		log.Println("Warning: 'server.bind_ip' ist in der Konfiguration nicht gesetzt. Standardmäßig auf 'localhost' gesetzt.")
		bindIP = "localhost"
	} else {
		var ok bool
		bindIP, ok = bindIPValue.(string)
		if !ok {
			log.Fatalf("Konfigurationsfehler: 'server.bind_ip' sollte ein String sein, aber %T wurde gefunden.", bindIPValue)
		}
	}

	// Konstruktion der prometheusURL basierend auf 'bind_ip' und 'metricsport'
	prometheusURL = fmt.Sprintf("http://%s:%d/metrics", bindIP, port)
	log.Printf("Metrics URL gesetzt auf: %s", prometheusURL)

	// Log-Datei auslesen über server.logfile
	logFileValue := config.Get("server.logfile")
	if logFileValue == nil {
		log.Println("Warning: 'server.logfile' is missing, using default '/var/log/hmac-file-server.log'")
		logFilePath = "/var/log/hmac-file-server.log"
	} else {
		lf, ok := logFileValue.(string)
		if !ok {
			log.Fatalf("Error: 'server.logfile' is not of type string, got %T", logFileValue)
		}
		logFilePath = lf
	}
}

// Thresholds for color coding
const (
	HighUsage   = 80.0
	MediumUsage = 50.0
)

// ProcessInfo holds information about a process
type ProcessInfo struct {
	PID                   int32
	Name                  string
	CPUPercent            float64
	MemPercent            float32
	CommandLine           string
	Uptime                string // Neues Feld für die Uptime
	Status                string // Neues Feld für den Status
	ErrorCount            int    // Neues Feld für die Anzahl der Fehler
	TotalRequests         int64  // Neues Feld für die Gesamtanzahl der Anfragen
	ActiveConnections     int    // Neues Feld für aktive Verbindungen
	AverageResponseTime   float64 // Neues Feld für die durchschnittliche Antwortzeit in Millisekunden
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
			name == "goroutines_count" ||
			name == "total_requests" ||
			name == "average_response_time_ms" {

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

// Funktion zum Abrufen der Prozessliste mit paralleler Verarbeitung
func fetchProcessList() ([]ProcessInfo, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch processes: %w", err)
	}

	var processList []ProcessInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Begrenzung der gleichzeitigen Goroutinen auf 10
	sem := make(chan struct{}, 10)

	for _, p := range processes {
		wg.Add(1)
		sem <- struct{}{} // Eintritt in semaphor

		go func(p *process.Process) {
			defer wg.Done()
			defer func() { <-sem }() // Austritt aus semaphor

			cpuPercent, err := p.CPUPercent()
			if err != nil {
				return
			}

			memPercent, err := p.MemoryPercent()
			if err != nil {
				return
			}

			name, err := p.Name()
			if err != nil {
				return
			}

			cmdline, err := p.Cmdline()
			if err != nil {
				cmdline = ""
			}

			info := ProcessInfo{
				PID:         p.Pid,
				Name:        name,
				CPUPercent:  cpuPercent,
				MemPercent:  memPercent,
				CommandLine: cmdline,
			}

			mu.Lock()
			processList = append(processList, info)
			mu.Unlock()
		}(p)
	}

	wg.Wait()
	return processList, nil
}

// Function to fetch detailed information about hmac-file-server
func fetchHmacFileServerInfo() (*ProcessInfo, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch processes: %w", err)
	}

	for _, p := range processes {
		name, err := p.Name()
		if err != nil {
			continue
		}

		if name == "hmac-file-server" {
			cpuPercent, err := p.CPUPercent()
			if err != nil {
				cpuPercent = 0.0
			}

			memPercent, err := p.MemoryPercent()
			if err != nil {
				memPercent = 0.0
			}

			cmdline, err := p.Cmdline()
			if err != nil {
				cmdline = ""
			}

			createTime, err := p.CreateTime()
			if err != nil {
				return nil, fmt.Errorf("failed to get process start time: %w", err)
			}
			uptime := time.Since(time.Unix(0, createTime*int64(time.Millisecond)))

			status := "Running" // Standardstatus

			// Überprüfung, ob der Prozess aktiv ist
			isRunning, err := p.IsRunning()
			if err != nil || !isRunning {
				status = "Stopped"
			}

			errorCount, err := countHmacErrors()
			if err != nil {
				errorCount = 0
			}

			metrics, err := fetchMetrics()
			if err != nil {
				return nil, fmt.Errorf("failed to fetch metrics: %w", err)
			}

			totalRequests, ok := metrics["total_requests"]
			if !ok {
				totalRequests = 0
			}

			activeConnections, ok := metrics["active_connections_total"]
			if !ok {
				activeConnections = 0
			}

			averageResponseTime, ok := metrics["average_response_time_ms"]
			if !ok {
				averageResponseTime = 0.0
			}

			return &ProcessInfo{
				PID:                 p.Pid,
				Name:                name,
				CPUPercent:          cpuPercent,
				MemPercent:          memPercent,
				CommandLine:         cmdline,
				Uptime:              uptime.String(),
				Status:              status,
				ErrorCount:          errorCount,
				TotalRequests:       int64(totalRequests),
				ActiveConnections:   int(activeConnections),
				AverageResponseTime: averageResponseTime,
			}, nil
		}
	}

	return nil, fmt.Errorf("hmac-file-server process not found")
}

// Neue Funktion zur Zählung der Fehler in den Logs
func countHmacErrors() (int, error) {
	logFilePath := "/var/log/hmac-file-server.log" // Pfad zur Logdatei
	file, err := os.Open(logFilePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	errorCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "level=error") {
			errorCount++
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return errorCount, nil
}

// Funktion zur Aktualisierung der UI mit paralleler Datenbeschaffung
func updateUI(ctx context.Context, app *tview.Application, pages *tview.Pages, sysPage, hmacPage tview.Primitive) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Einführung von Channels für verschiedene Daten
	systemDataCh := make(chan struct {
		memUsage float64
		cpuUsage float64
		cores    int
		err      error
	})
	var metricsCh chan struct {
		metrics map[string]float64
		err     error
	}
	if metricsEnabled {
		metricsCh = make(chan struct {
			metrics map[string]float64
			err     error
		})
	}
	processListCh := make(chan struct {
		processes []ProcessInfo
		err       error
	})
	hmacInfoCh := make(chan struct {
		info    *ProcessInfo
		metrics map[string]float64
		err     error
	})

	// Goroutine zur Datenbeschaffung
	go func() {
		for {
			select {
			case <-ctx.Done():
				close(systemDataCh)
				if metricsEnabled {
					close(metricsCh)
				}
				close(processListCh)
				close(hmacInfoCh)
				return
			case <-ticker.C:
				// Systemdaten abrufen asynchron
				go func() {
					memUsage, cpuUsage, cores, err := fetchSystemData()
					systemDataCh <- struct {
						memUsage float64
						cpuUsage float64
						cores    int
						err      error
					}{memUsage, cpuUsage, cores, err}
				}()

				if metricsEnabled {
					// Metriken abrufen asynchron
					go func() {
						metrics, err := fetchMetrics()
						metricsCh <- struct {
							metrics map[string]float64
							err     error
						}{metrics, err}
					}()
				}

				// Prozessliste abrufen asynchron
				go func() {
					processes, err := fetchProcessList()
					processListCh <- struct {
						processes []ProcessInfo
						err       error
					}{processes, err}
				}()

				// hmac-file-server Informationen abrufen asynchron
				go func() {
					hmacInfo, err := fetchHmacFileServerInfo()
					var metrics map[string]float64
					if metricsEnabled {
						metrics, err = fetchMetrics()
					}
					hmacInfoCh <- struct {
						info    *ProcessInfo
						metrics map[string]float64
						err     error
					}{hmacInfo, metrics, err}
				}()
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-systemDataCh:
			if !ok {
				systemDataCh = nil
				continue
			}
			if data.err != nil {
				log.Printf("Fehler beim Abrufen der Systemdaten: %v\n", data.err)
				continue
			}
			// UI aktualisieren mit Systemdaten
			app.QueueUpdateDraw(func() {
				if currentPage, _ := pages.GetFrontPage(); currentPage == "system" {
					sysFlex := sysPage.(*tview.Flex)
					sysTable := sysFlex.GetItem(0).(*tview.Table)
					updateSystemTable(sysTable, data.memUsage, data.cpuUsage, data.cores)
				}
			})
		case data, ok := <-metricsCh:
			if !ok {
				metricsCh = nil
				continue
			}
			if data.err != nil {
				log.Printf("Fehler beim Abrufen der Metriken: %v\n", data.err)
				continue
			}
			// UI aktualisieren mit Metriken
			app.QueueUpdateDraw(func() {
				if currentPage, _ := pages.GetFrontPage(); currentPage == "system" {
					sysFlex := sysPage.(*tview.Flex)
					metricsTable := sysFlex.GetItem(1).(*tview.Table)
					updateMetricsTable(metricsTable, data.metrics)
				}
			})
		case data, ok := <-processListCh:
			if !ok {
				processListCh = nil
				continue
			}
			if data.err != nil {
				log.Printf("Fehler beim Abrufen der Prozessliste: %v\n", data.err)
				continue
			}
			// UI aktualisieren mit Prozessliste
			app.QueueUpdateDraw(func() {
				if currentPage, _ := pages.GetFrontPage(); currentPage == "system" {
					sysFlex := sysPage.(*tview.Flex)
					processTable := sysFlex.GetItem(2).(*tview.Table)
					updateProcessTable(processTable, data.processes)
				}
			})
		case data, ok := <-hmacInfoCh:
			if !ok {
				hmacInfoCh = nil
				continue
			}
			if data.err != nil {
				log.Printf("Fehler beim Abrufen der hmac-file-server Informationen: %v\n", data.err)
				continue
			}
			// UI aktualisieren mit hmac-file-server Informationen
			app.QueueUpdateDraw(func() {
				if currentPage, _ := pages.GetFrontPage(); currentPage == "hmac" && data.info != nil {
					hmacFlex := hmacPage.(*tview.Flex)
					hmacTable := hmacFlex.GetItem(0).(*tview.Table)
					updateHmacTable(hmacTable, data.info, data.metrics)
				}
			})
		}

		// Abbruchbedingung, wenn alle Channels geschlossen sind
		if systemDataCh == nil && (!metricsEnabled || metricsCh == nil) && processListCh == nil && hmacInfoCh == nil {
			break
		}
	}
}

// Helper function to update system data table
func updateSystemTable(sysTable *tview.Table, memUsage, cpuUsage float64, cores int) {
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
}

// Helper function to update metrics table
func updateMetricsTable(metricsTable *tview.Table, metrics map[string]float64) {
	metricsTable.Clear()
	metricsTable.SetCell(0, 0, tview.NewTableCell("Metric").SetAttributes(tcell.AttrBold))
	metricsTable.SetCell(0, 1, tview.NewTableCell("Value").SetAttributes(tcell.AttrBold))

	row := 1
	for key, value := range metrics {
		metricsTable.SetCell(row, 0, tview.NewTableCell(key))
		metricsTable.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%.2f", value)))
		row++
	}
}

// Helper function to update process table
func updateProcessTable(processTable *tview.Table, processes []ProcessInfo) {
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
}

// Helper function to update hmac-table
func updateHmacTable(hmacTable *tview.Table, hmacInfo *ProcessInfo, metrics map[string]float64) {
	hmacTable.Clear()
	hmacTable.SetCell(0, 0, tview.NewTableCell("Property").SetAttributes(tcell.AttrBold))
	hmacTable.SetCell(0, 1, tview.NewTableCell("Value").SetAttributes(tcell.AttrBold))

	// Process information
	hmacTable.SetCell(1, 0, tview.NewTableCell("PID"))
	hmacTable.SetCell(1, 1, tview.NewTableCell(fmt.Sprintf("%d", hmacInfo.PID)))

	hmacTable.SetCell(2, 0, tview.NewTableCell("CPU%"))
	hmacTable.SetCell(2, 1, tview.NewTableCell(fmt.Sprintf("%.2f", hmacInfo.CPUPercent)))

	hmacTable.SetCell(3, 0, tview.NewTableCell("Mem%"))
	hmacTable.SetCell(3, 1, tview.NewTableCell(fmt.Sprintf("%.2f", hmacInfo.MemPercent)))

	hmacTable.SetCell(4, 0, tview.NewTableCell("Command"))
	hmacTable.SetCell(4, 1, tview.NewTableCell(hmacInfo.CommandLine))
	
	hmacTable.SetCell(5, 0, tview.NewTableCell("Uptime"))
	hmacTable.SetCell(5, 1, tview.NewTableCell(hmacInfo.Uptime)) // Neue Zeile für Uptime
	
	hmacTable.SetCell(6, 0, tview.NewTableCell("Status"))
	hmacTable.SetCell(6, 1, tview.NewTableCell(hmacInfo.Status)) // Neue Zeile für Status
	
	hmacTable.SetCell(7, 0, tview.NewTableCell("Error Count"))
	hmacTable.SetCell(7, 1, tview.NewTableCell(fmt.Sprintf("%d", hmacInfo.ErrorCount))) // Neue Zeile für Error Count

	hmacTable.SetCell(8, 0, tview.NewTableCell("Total Requests"))
	hmacTable.SetCell(8, 1, tview.NewTableCell(fmt.Sprintf("%d", hmacInfo.TotalRequests))) // Neue Zeile für Total Requests

	hmacTable.SetCell(9, 0, tview.NewTableCell("Active Connections"))
	hmacTable.SetCell(9, 1, tview.NewTableCell(fmt.Sprintf("%d", hmacInfo.ActiveConnections))) // Neue Zeile für Active Connections

	hmacTable.SetCell(10, 0, tview.NewTableCell("Avg. Response Time (ms)"))
	hmacTable.SetCell(10, 1, tview.NewTableCell(fmt.Sprintf("%.2f", hmacInfo.AverageResponseTime))) // Neue Zeile für Average Response Time

	// Metrics related to hmac-file-server
	row := 12
	hmacTable.SetCell(row, 0, tview.NewTableCell("Metric").SetAttributes(tcell.AttrBold))
	hmacTable.SetCell(row, 1, tview.NewTableCell("Value").SetAttributes(tcell.AttrBold))
	row++

	for key, value := range metrics {
		if strings.Contains(key, "hmac_file_server_") {
			hmacTable.SetCell(row, 0, tview.NewTableCell(key))
			hmacTable.SetCell(row, 1, tview.NewTableCell(fmt.Sprintf("%.2f", value)))
			row++
		}
	}
}

func createSystemPage() tview.Primitive {
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
	sysFlex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(sysTable, 7, 0, false).
		AddItem(metricsTable, 0, 1, false).
		AddItem(processTable, 0, 2, false)

	return sysFlex
}

func createHmacPage() tview.Primitive {
	hmacTable := tview.NewTable().SetBorders(false)
	hmacTable.SetTitle(" [::b]hmac-file-server Details ").SetBorder(true)

	hmacFlex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(hmacTable, 0, 1, false)

	return hmacFlex
}

func createLogsPage(ctx context.Context, app *tview.Application, logFilePath string) tview.Primitive {
	logsTextView := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWordWrap(true)
	logsTextView.SetTitle(" [::b]Logs ").SetBorder(true)

	const numLines = 100 // Number of lines to read from the end of the log file

	// Read logs periodically
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				content, err := readLastNLines(logFilePath, numLines)
				if err != nil {
					app.QueueUpdateDraw(func() {
						logsTextView.SetText(fmt.Sprintf("[red]Error reading log file: %v[white]", err))
					})
				} else {
					// Process the log content to add colors
					lines := strings.Split(content, "\n")
					var coloredLines []string
					for _, line := range lines {
						if strings.Contains(line, "level=info") {
							coloredLines = append(coloredLines, "[green]"+line+"[white]")
						} else if strings.Contains(line, "level=warn") {
							coloredLines = append(coloredLines, "[yellow]"+line+"[white]")
						} else if strings.Contains(line, "level=error") {
							coloredLines = append(coloredLines, "[red]"+line+"[white]")
						} else {
							// Default color
							coloredLines = append(coloredLines, line)
						}
					}
					app.QueueUpdateDraw(func() {
						logsTextView.SetText(strings.Join(coloredLines, "\n"))
					})
				}
				time.Sleep(2 * time.Second) // Refresh interval for logs
			}
		}
	}()

	return logsTextView
}

// Optimized readLastNLines to handle large files efficiently
func readLastNLines(filePath string, n int) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	const bufferSize = 1024
	buffer := make([]byte, bufferSize)
	var content []byte
	var fileSize int64

	fileInfo, err := file.Stat()
	if err != nil {
		return "", err
	}
	fileSize = fileInfo.Size()

	var offset int64 = 0
	for {
		if fileSize-offset < bufferSize {
			offset = fileSize
		} else {
			offset += bufferSize
		}

		_, err := file.Seek(-offset, io.SeekEnd)
		if err != nil {
			return "", err
		}

		bytesRead, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return "", err
		}

		content = append(buffer[:bytesRead], content...)

		if bytesRead < bufferSize || len(strings.Split(string(content), "\n")) > n+1 {
			break
		}

		if offset >= fileSize {
			break
		}
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n"), nil
}

func main() {
	app := tview.NewApplication()

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create pages
	pages := tview.NewPages()

	// System page
	sysPage := createSystemPage()
	pages.AddPage("system", sysPage, true, true)

	// hmac-file-server page
	hmacPage := createHmacPage()
	pages.AddPage("hmac", hmacPage, true, false)

	// Logs page mit dem gelesenen logFilePath
	logsPage := createLogsPage(ctx, app, logFilePath)
	pages.AddPage("logs", logsPage, true, false)

	// Add key binding to switch views and handle exit
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyRune {
			switch event.Rune() {
			case 'q', 'Q':
				cancel()
				app.Stop()
				return nil
			case 's', 'S':
				// Switch to system page
				pages.SwitchToPage("system")
			case 'h', 'H':
				// Switch to hmac-file-server page
				pages.SwitchToPage("hmac")
			case 'l', 'L':
				// Switch to logs page
				pages.SwitchToPage("logs")
			}
		}
		return event
	})

	// Start the UI update loop in a separate goroutine
	go updateUI(ctx, app, pages, sysPage, hmacPage)

	// Set the root and run the application
	if err := app.SetRoot(pages, true).EnableMouse(true).Run(); err != nil {
		log.Fatalf("Error running application: %v", err)
		log.Fatalf("Error running application: %v", err)
	}
}