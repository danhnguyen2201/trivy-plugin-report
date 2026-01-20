package main

import (
    "encoding/json"
    "fmt"
    "os"
    "strings"

    "github.com/aquasecurity/trivy/pkg/log"
    "github.com/aquasecurity/trivy/pkg/types"
    "github.com/spf13/cobra"
    
    "trivy-plugin-excel/pkg/excel" 
    "trivy-plugin-excel/pkg/pdf" // Đảm bảo bạn đã tạo package này
)

func main() {
    var outputBase string
    var beautify bool

    var rootCmd = &cobra.Command{
        Use:   "report",
        Short: "Trivy plugin to export scan results to Excel and PDF",
        Long:  "Reads Trivy JSON from stdin and generates both Excel and PDF reports.",
        Run: func(cmd *cobra.Command, args []string) {
            var report types.Report
            
            // Đọc dữ liệu từ Stdin
            if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
                log.Fatal("Error: Plugin requires Trivy JSON input via stdin. Usage: trivy image -f json <target> | trivy report")
            }

            // Loại bỏ phần mở rộng nếu người dùng nhập (ví dụ: report.xlsx -> report)
            outputBase = strings.TrimSuffix(outputBase, ".xlsx")
            outputBase = strings.TrimSuffix(outputBase, ".pdf")

            // 1. Xuất file Excel
            excelPath := outputBase + ".xlsx"
            log.Infof("Generating Excel report: %s", excelPath)
            if err := excel.Export(&report, excelPath, beautify); err != nil {
                log.Errorf("Failed to export Excel: %v", err)
            }

            // 2. Xuất file PDF
            pdfPath := outputBase + ".pdf"
            log.Infof("Generating PDF report: %s", pdfPath)
            if err := pdf.Export(report, pdfPath); err != nil {
                log.Errorf("Failed to export PDF: %v", err)
            }

            fmt.Println("✨ All reports generated successfully!")
        },
    }

    // Đổi mặc định thành tên base để không gây nhầm lẫn
    rootCmd.Flags().StringVarP(&outputBase, "output", "o", "trivy-report", "Base path for output files (extensions .xlsx and .pdf will be added)")
    rootCmd.Flags().BoolVarP(&beautify, "beautify", "b", true, "Enable severity background coloring (Excel only)")

    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}