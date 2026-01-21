package csv

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/aquasecurity/trivy/pkg/types"
)

// Export xuất kết quả scan ra file CSV sử dụng thư viện chuẩn encoding/csv
func Export(report *types.Report, path string) error {
	// 1. Tạo file
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	// 2. Khởi tạo Writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 3. Viết Header
	header := []string{
		"Target",
		"Type",
		"Vulnerability ID",
		"Severity",
		"Pkg Name",
		"Installed Version",
		"Fixed Version",
		"Title",
		"Primary URL",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// 4. Duyệt và ghi dữ liệu
	for _, result := range report.Results {
		// Nếu không có lỗ hổng nào, bỏ qua hoặc có thể ghi dòng trắng tùy nhu cầu
		if len(result.Vulnerabilities) == 0 {
			continue
		}

		for _, vuln := range result.Vulnerabilities {
			// Xử lý dữ liệu text để tránh lỗi format CSV (thư viện encoding/csv tự xử lý quote, nhưng ta cần clean string)
			fixedVer := vuln.FixedVersion
			if fixedVer == "" {
				fixedVer = "-"
			}

			// Lấy URL đầu tiên làm tham chiếu
			primaryURL := ""
			if len(vuln.References) > 0 {
				primaryURL = vuln.References[0]
			}

			row := []string{
				result.Target,
				string(result.Class),
				vuln.VulnerabilityID,
				vuln.Severity,
				vuln.PkgName,
				vuln.InstalledVersion,
				fixedVer,
				vuln.Title,
				primaryURL,
			}

			if err := writer.Write(row); err != nil {
				return fmt.Errorf("error writing record for %s: %w", vuln.VulnerabilityID, err)
			}
		}
	}

	return nil
}