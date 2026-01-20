package pdf

import (
    "github.com/aquasecurity/trivy/pkg/types"
    "github.com/jung-kurt/gofpdf"
)

// SỬA Ở ĐÂY: Thêm dấu * trước types.Report
func Export(report *types.Report, path string) error {
    pdf := gofpdf.New("P", "mm", "A4", "")
    pdf.AddPage()
    
    // Header
    pdf.SetFont("Arial", "B", 16)
    pdf.Cell(0, 10, "Trivy Vulnerability Report")
    pdf.Ln(12)

    for _, result := range report.Results {
        pdf.SetFont("Arial", "B", 12)
        pdf.SetFillColor(240, 240, 240)
        // Lưu ý: gofpdf mặc định không hỗ trợ tiếng Việt có dấu (UTF-8). 
        // Nếu Target chứa tiếng Việt có thể bị lỗi font.
        pdf.CellFormat(0, 8, "Target: "+result.Target, "1", 1, "L", true, 0, "")
        pdf.Ln(2)

        // Table Header
        pdf.SetFont("Arial", "B", 10)
        pdf.SetFillColor(200, 200, 200)
        pdf.CellFormat(45, 7, "ID", "1", 0, "C", true, 0, "")
        pdf.CellFormat(30, 7, "Severity", "1", 0, "C", true, 0, "")
        pdf.CellFormat(115, 7, "Title", "1", 1, "C", true, 0, "")

        // Table Body
        pdf.SetFont("Arial", "", 9)
        for _, v := range result.Vulnerabilities {
            pdf.CellFormat(45, 6, v.VulnerabilityID, "1", 0, "L", false, 0, "")
            pdf.CellFormat(30, 6, v.Severity, "1", 0, "C", false, 0, "")
            
            // Cắt ngắn Title nếu quá dài để tránh vỡ layout (gofpdf không tự xuống dòng trong CellFormat đơn giản)
            title := v.Title
            if len(title) > 80 {
                title = title[:77] + "..."
            }
            pdf.CellFormat(115, 6, title, "1", 1, "L", false, 0, "")
        }
        pdf.Ln(10)
    }

    return pdf.OutputFileAndClose(path)
}