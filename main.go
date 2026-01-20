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

	"trivy-plugin-excel/pkg/excel"
	"trivy-plugin-excel/pkg/pdf"
)

func main() {
	var output string
	var beautify bool

	var rootCmd = &cobra.Command{
		Use:   "report",
		Short: "Export Trivy results to Excel and PDF",
		Run: func(cmd *cobra.Command, args []string) {
			var report types.Report
			if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
				// Sửa lỗi: Dùng log.Fatal trực tiếp
				log.Fatal("Error reading JSON input: %v", err)
			}

			ext := filepath.Ext(output)
			baseName := strings.TrimSuffix(output, ext)
			if baseName == "" {
				baseName = "report"
			}

			log.Infof("Generating reports with base name: %s", baseName)

			var wg sync.WaitGroup
			wg.Add(2)

			// Luồng 1: Excel
			go func() {
				defer wg.Done()
				fileName := baseName + ".xlsx"
				if err := excel.Export(&report, fileName, beautify); err != nil {
					// SỬA LỖI 1: Thay log.Logger.Errorf bằng log.Errorf
					log.Errorf("Failed to export Excel: %v", err)
				} else {
					log.Infof("Created: %s", fileName)
				}
			}()

			// Luồng 2: PDF
			go func() {
				defer wg.Done()
				fileName := baseName + ".pdf"
				// Lưu ý: Nhớ sửa file pkg/pdf/export.go thêm dấu * vào func Export(report *types.Report...)
				if err := pdf.Export(&report, fileName); err != nil {
					// SỬA LỖI 1: Thay log.Logger.Errorf bằng log.Errorf
					log.Errorf("Failed to export PDF: %v", err)
				} else {
					log.Infof("Created: %s", fileName)
				}
			}()

			wg.Wait()
			log.Infof("All reports generated!")
		},
	}

	rootCmd.Flags().StringVarP(&output, "output", "o", "report", "Base filename (without extension)")
	rootCmd.Flags().BoolVarP(&beautify, "beautify", "b", true, "Enable coloring (Excel only)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}