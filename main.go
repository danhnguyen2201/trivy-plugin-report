package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync" // Dùng để chạy song song (nhanh hơn)

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
				log.Fatal("Error reading JSON input: %v", err)
			}

			// 1. Xử lý tên file
			// Nếu người dùng nhập "ketqua.xlsx" hoặc "ketqua.pdf" -> ta cắt bỏ đuôi để lấy chữ "ketqua"
			ext := filepath.Ext(output)
			baseName := strings.TrimSuffix(output, ext)
			
			// Nếu người dùng không nhập gì, mặc định là "report"
			if baseName == "" {
				baseName = "report"
			}

			log.Infof("Generating reports with base name: %s", baseName)

			// 2. Sử dụng WaitGroup để xuất 2 file cùng lúc (Goroutines)
			var wg sync.WaitGroup
			wg.Add(2)

			// Luồng 1: Xuất Excel
			go func() {
				defer wg.Done()
				fileName := baseName + ".xlsx"
				if err := excel.Export(&report, fileName, beautify); err != nil {
					log.Logger.Errorf("Failed to export Excel: %v", err)
				} else {
					log.Infof("Created: %s", fileName)
				}
			}()

			// Luồng 2: Xuất PDF
			go func() {
				defer wg.Done()
				fileName := baseName + ".pdf"
				// Lưu ý: Hàm pdf.Export của bạn cần khớp tham số (ở bài trước là Export(report, filename))
				if err := pdf.Export(&report, fileName); err != nil {
					log.Logger.Errorf("Failed to export PDF: %v", err)
				} else {
					log.Infof("Created: %s", fileName)
				}
			}()

			// Chờ cả 2 luồng chạy xong
			wg.Wait()
			log.Infof("All reports generated!")
		},
	}

	// Sửa lại mô tả flag cho phù hợp
	rootCmd.Flags().StringVarP(&output, "output", "o", "report", "Base filename (without extension)")
	rootCmd.Flags().BoolVarP(&beautify, "beautify", "b", true, "Enable coloring (Excel only)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}