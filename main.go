package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/spf13/cobra"
	"trivy-plugin-excel/pkg/csv"
	"trivy-plugin-excel/pkg/excel"
	"trivy-plugin-excel/pkg/pdf"
)

func main() {
	var output string
	var beautify bool

	var rootCmd = &cobra.Command{
		Use:   "report",
		Short: "Export Trivy results to Excel, PDF and CSV",
		Run: func(cmd *cobra.Command, args []string) {
			var report types.Report
			if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
				log.Fatal("Error reading JSON input: %v", err)
			}

			ext := strings.ToLower(filepath.Ext(output))
			baseName := strings.TrimSuffix(output, filepath.Ext(output))
			
			if baseName == "" {
				baseName = "report"
			}

			// 2. Xác định định dạng cần xuất
			var exportExcel, exportPdf, exportCsv bool
			
			switch ext {
			case ".xlsx":
				exportExcel = true
			case ".pdf":
				exportPdf = true
			case ".csv":
				exportCsv = true
			case "":
				// Nếu không nhập đuôi, xuất TẤT CẢ định dạng
				exportExcel = true
				exportPdf = true
				exportCsv = true
			default:
				log.Fatal("Unsupported file extension: " + ext + ". Use .xlsx, .pdf or .csv")
			}

			log.Infof("Generating reports for: %s", output)

			var wg sync.WaitGroup

			// Luồng 1: Excel
			if exportExcel {
				wg.Add(1)
				go func() {
					defer wg.Done()
					fileName := baseName + ".xlsx"
					if err := excel.Export(&report, fileName, beautify); err != nil {
						log.Errorf("Failed to export Excel: %v", err)
					} else {
						log.Infof("Created: %s", fileName)
					}
				}()
			}

			// Luồng 2: PDF
			if exportPdf {
				wg.Add(1)
				go func() {
					defer wg.Done()
					fileName := baseName + ".pdf"
					if err := pdf.Export(&report, fileName); err != nil {
						log.Errorf("Failed to export PDF: %v", err)
					} else {
						log.Infof("Created: %s", fileName)
					}
				}()
			}

			// Luồng 3: CSV (Mới thêm)
			if exportCsv {
				wg.Add(1)
				go func() {
					defer wg.Done()
					fileName := baseName + ".csv"
					// CSV không cần option beautify
					if err := csv.Export(&report, fileName); err != nil {
						log.Errorf("Failed to export CSV: %v", err)
					} else {
						log.Infof("Created: %s", fileName)
					}
				}()
			}

			wg.Wait()
			log.Infof("Completed!")
		},
	}

	rootCmd.Flags().StringVarP(&output, "output", "o", "report", "Output filename (e.g., report.xlsx, report.pdf, report.csv)")
	rootCmd.Flags().BoolVarP(&beautify, "beautify", "b", true, "Enable coloring (Excel only)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}