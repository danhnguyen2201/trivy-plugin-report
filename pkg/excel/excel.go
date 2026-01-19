package excel

import (
	"fmt"

	// dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	//"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/xuri/excelize/v2"
	"golang.org/x/xerrors"
)

const (
	VulnReport = "Vulnerability Scan Report"
)

var (
	// Mapping Class to English
	ResultClass = map[types.ResultClass]string{
		types.ClassOSPkg:   "OS Packages",
		types.ClassLangPkg: "Language Packages",
	}

	// Severity Colors (Hex codes)
	SeverityColor = map[string]string{
		"CRITICAL": "FF7675", // Deep Red
		"HIGH":     "FAB1A0", // Light Red/Orange
		"MEDIUM":   "FFEAA7", // Yellow
		"LOW":      "74B9FF", // Light Blue
		"UNKNOWN":  "DFE6E9", // Grey
	}

	VulnHeaderValues = []string{
		"Target", "Type", "Class", "Vulnerability ID", "Title",
		"Severity Source", "Severity", "Package Name", "Installed Version", "Path",
		"Fixed Version", "Status",
	}

	VulnHeaderWidths = map[string]float64{
		"A": 25, "B": 15, "C": 15, "D": 20, "E": 40,
		"F": 15, "G": 12, "H": 20, "I": 20, "J": 30,
		"K": 20, "L": 15,
	}

	DefaultStyle = excelize.Style{
		Alignment: &excelize.Alignment{WrapText: true, Vertical: "top", Horizontal: "left"},
		Border: []excelize.Border{
			{Type: "left", Style: 1, Color: "000000"},
			{Type: "top", Style: 1, Color: "000000"},
			{Type: "right", Style: 1, Color: "000000"},
			{Type: "bottom", Style: 1, Color: "000000"},
		},
	}
)

func Export(report *types.Report, fileName string, beautify bool) error {
	f := excelize.NewFile()
	hasVuln := false
	rowNum := 2

	for _, result := range report.Results {
		if len(result.Vulnerabilities) > 0 {
			hasVuln = true
			if err := createVulnSheet(f); err != nil {
				return err
			}
			if err := createVulnHeaders(f); err != nil {
				return err
			}

			for _, vuln := range result.Vulnerabilities {
				data := parseVulnData(result.Target, result.Type, result.Class, vuln)
				
				cell, _ := excelize.CoordinatesToCellName(1, rowNum)
				if err := f.SetSheetRow(VulnReport, cell, &data); err != nil {
					return xerrors.Errorf("failed to add row: %w", err)
				}

				// Apply Style and Coloring
				if err := setRowStyle(f, rowNum, vuln.Severity, beautify); err != nil {
					return err
				}
				rowNum++
			}
		}
	}

	f.DeleteSheet("Sheet1")
	if hasVuln {
		return f.SaveAs(fileName)
	}
	return nil
}

func createVulnSheet(f *excelize.File) error {
	index, _ := f.GetSheetIndex(VulnReport)
	if index == -1 {
		_, err := f.NewSheet(VulnReport)
		return err
	}
	return nil
}

func createVulnHeaders(f *excelize.File) error {
	f.SetSheetRow(VulnReport, "A1", &VulnHeaderValues)
	for col, width := range VulnHeaderWidths {
		f.SetColWidth(VulnReport, col, col, width)
	}
	return nil
}

func setRowStyle(f *excelize.File, rowNum int, severity string, beautify bool) error {
	style := DefaultStyle
	if beautify {
		if color, ok := SeverityColor[severity]; ok {
			style.Fill = excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{color}}
		}
	}

	styleID, _ := f.NewStyle(&style)
	startCell := fmt.Sprintf("A%d", rowNum)
	endCell := fmt.Sprintf("L%d", rowNum)
	return f.SetCellStyle(VulnReport, startCell, endCell, styleID)
}

func parseVulnData(target string, rType ftypes.TargetType, rClass types.ResultClass, vuln types.DetectedVulnerability) []string {
	classStr := string(rClass)
	if v, ok := ResultClass[rClass]; ok {
		classStr = v
	}

	return []string{
		target,
		string(rType),
		classStr,
		vuln.VulnerabilityID,
		vuln.Title,
		string(vuln.SeveritySource),
		vuln.Severity,
		vuln.PkgName,
		vuln.InstalledVersion,
		vuln.PkgPath,
		vuln.FixedVersion,
		vuln.Status.String(),
	}
}