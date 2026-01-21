package pdf

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/johnfercher/maroto/v2"
	"github.com/johnfercher/maroto/v2/pkg/components/line"
	"github.com/johnfercher/maroto/v2/pkg/components/row"
	"github.com/johnfercher/maroto/v2/pkg/components/text"
	"github.com/johnfercher/maroto/v2/pkg/config"
	"github.com/johnfercher/maroto/v2/pkg/consts/align"
	"github.com/johnfercher/maroto/v2/pkg/consts/border"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontfamily"
	"github.com/johnfercher/maroto/v2/pkg/consts/fontstyle"
	"github.com/johnfercher/maroto/v2/pkg/consts/orientation"
	"github.com/johnfercher/maroto/v2/pkg/consts/pagesize"
	"github.com/johnfercher/maroto/v2/pkg/core"
	"github.com/johnfercher/maroto/v2/pkg/props"
)

// --- 1. PRE-DEFINED COLORS ---

var (
	// Text Colors
	ColorHeaderOpen = &props.Color{Red: 20, Green: 20, Blue: 20}
	ColorHeaderText = &props.Color{Red: 40, Green: 40, Blue: 40}
	ColorBodyText   = &props.Color{Red: 50, Green: 50, Blue: 50}
	ColorDarkGray   = &props.Color{Red: 30, Green: 30, Blue: 30}
	ColorLightGray  = &props.Color{Red: 150, Green: 150, Blue: 150}
	ColorGrayText   = &props.Color{Red: 100, Green: 100, Blue: 100}

	// Severity Text Colors
	ColorSevCritical = &props.Color{Red: 220, Green: 50, Blue: 50}
	ColorSevHigh     = &props.Color{Red: 220, Green: 100, Blue: 0}
	ColorSevMedium   = &props.Color{Red: 220, Green: 160, Blue: 0}
	ColorSevLow      = &props.Color{Red: 180, Green: 180, Blue: 0}
	ColorSevDefault  = &props.Color{Red: 80, Green: 80, Blue: 80}

	// Background Colors
	ColorBgHeader   = &props.Color{Red: 240, Green: 240, Blue: 240}
	ColorBgCritical = &props.Color{Red: 255, Green: 235, Blue: 235}
	ColorBgHigh     = &props.Color{Red: 255, Green: 245, Blue: 235}
	ColorBgMedium   = &props.Color{Red: 255, Green: 250, Blue: 235}
	ColorBgLow      = &props.Color{Red: 250, Green: 250, Blue: 235}
	ColorBgWhite    = &props.Color{Red: 255, Green: 255, Blue: 255}
)

func getSeverityColor(severity string) *props.Color {
	switch severity {
	case "CRITICAL":
		return ColorSevCritical
	case "HIGH":
		return ColorSevHigh
	case "MEDIUM":
		return ColorSevMedium
	case "LOW":
		return ColorSevLow
	default:
		return ColorSevDefault
	}
}

func getBackgroundColor(severity string) *props.Color {
	switch severity {
	case "CRITICAL":
		return ColorBgCritical
	case "HIGH":
		return ColorBgHigh
	case "MEDIUM":
		return ColorBgMedium
	case "LOW":
		return ColorBgLow
	default:
		return ColorBgWhite
	}
}

func getSeverityWeight(severity string) int {
	switch severity {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	default:
		return 1
	}
}

// --- 2. DATA PROCESSING ---

type SeverityCount struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
	Total    int
}

// countVulnerabilities aggregates vulnerability counts by severity.
func countVulnerabilities(report *types.Report) SeverityCount {
	var counts SeverityCount
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			counts.Total++
			switch v.Severity {
			case "CRITICAL":
				counts.Critical++
			case "HIGH":
				counts.High++
			case "MEDIUM":
				counts.Medium++
			case "LOW":
				counts.Low++
			default:
				counts.Unknown++
			}
		}
	}
	return counts
}

// calculateRowHeight calculates the row height dynamically (Auto Fit).
// It adjusts the height based on the length of "Pkg Name" and "Title" to ensure text fits on an A4 Landscape page.
func calculateRowHeight(pkgNameLen, titleLen int) float64 {
	// Estimation factors for characters per line:
	// - PkgName Column (Width 2/12 ~ 46mm): Fits approx. 18 characters.
	// - Title Column (Width 4/12 ~ 92mm): Fits approx. 45 characters.
	// If text length exceeds these limits, it wraps to the next line.
	
	pkgLines := (pkgNameLen + 17) / 18
	titleLines := (titleLen + 44) / 45

	maxLines := pkgLines
	if titleLines > maxLines {
		maxLines = titleLines
	}
	if maxLines < 1 {
		maxLines = 1
	}
	
	// Formula: Base Height (6) + (Lines * 4)
	// Added padding prevents text overlap.
	return 6.0 + (float64(maxLines) * 4.0)
}

// --- 3. MAIN EXPORT ---

// Export generates a PDF report from the Trivy scan results.
func Export(report *types.Report, path string) error {
	cfg := config.NewBuilder().
		WithOrientation(orientation.Horizontal). // Landscape mode
		WithPageSize(pagesize.A4).
		WithLeftMargin(10).
		WithTopMargin(10).
		WithRightMargin(10).
		Build()

	m := maroto.New(cfg)

	// --- Header ---
	m.RegisterHeader(
		text.NewRow(15, "Trivy Security Report", props.Text{
			Top:    2,
			Size:   20,
			Style:  fontstyle.Bold,
			Align:  align.Left,
			Family: fontfamily.Arial,
			Color:  ColorHeaderOpen,
		}),
	)

	// --- Dashboard Data ---
	counts := countVulnerabilities(report)
	currentTime := time.Now().Format("2006-01-02 15:04")

	// Spacer before Summary
	m.AddRows(row.New(5))

	// --- SUMMARY SECTION (BOXED) ---
	
	// 1. Summary Header (Gray background box)
	summaryHeader := row.New(8)
	summaryHeader.WithStyle(&props.Cell{
		BackgroundColor: ColorBgHeader,
		BorderType:      border.Full,
		BorderColor:     ColorLightGray,
	})
	summaryHeader.Add(
		text.NewCol(12, "SCAN SUMMARY", props.Text{
			Top:    1.5,
			Style:  fontstyle.Bold,
			Align:  align.Left,
			Family: fontfamily.Arial,
			Color:  ColorHeaderText,
			Size:   9,
		}),
	)
	m.AddRows(summaryHeader)

	// 2. Stats Row (White background box)
	statsRow := row.New(16)
	statsRow.WithStyle(&props.Cell{
		BorderType:  border.Full,
		BorderColor: ColorLightGray,
	})

	// Col 1: Date & Status
	statsRow.Add(
		text.NewCol(2, fmt.Sprintf("Date: %s \nStatus: Completed", currentTime), props.Text{
			Top:    3,
			Size:   9,
			Family: fontfamily.Arial,
			Color:  ColorBodyText,
			Align:  align.Left,
		}),
	)

	// Helper function for Stat Cols
	addStatCol := func(label string, count int, c *props.Color) core.Col {
		return text.NewCol(2, fmt.Sprintf("%d %s", count, label), props.Text{
			Top: 5, Size: 10, Style: fontstyle.Bold, Align: align.Center, Family: fontfamily.Arial, Color: c,
		})
	}

	statsRow.Add(
		addStatCol("Critical", counts.Critical, ColorSevCritical),
		addStatCol("High", counts.High, ColorSevHigh),
		addStatCol("Medium", counts.Medium, ColorSevMedium),
		addStatCol("Low", counts.Low, ColorSevLow),
	)

	if counts.Unknown > 0 {
		statsRow.Add(addStatCol("Unknown", counts.Unknown, ColorGrayText))
	} else {
		// Empty spacer if no unknown vulnerabilities
		statsRow.Add(text.NewCol(2, "", props.Text{}))
	}

	m.AddRows(statsRow)
	m.AddRows(row.New(10)) // Spacer after Summary

	// --- Table Configuration ---
	// Column configuration: ID(2), Sev(1), Pkg(2), Inst(2), Fixed(1), Title(4) -> Total Width: 12
	headers := []string{"ID", "Severity", "Pkg Name", "Installed", "Fixed", "Title"}
	colWidths := []int{2, 1, 2, 2, 1, 4}

	headerProp := props.Text{
		Top:    1.5,
		Style:  fontstyle.Bold,
		Color:  ColorHeaderText,
		Align:  align.Center,
		Family: fontfamily.Arial,
		Size:   9,
	}
	// Font size 8 for table body content
	bodyProp := props.Text{
		Top:    1.5,
		Size:   8,
		Family: fontfamily.Arial,
		Color:  ColorBodyText,
		Align:  align.Left,
	}

	// --- FIX PAGE NUMBER ISSUE ---
	// Maroto V2 does not support "$current / $total" placeholders in standard text components.
	// Instead, we use a static footer with a timestamp.
	m.RegisterFooter(
		row.New(5).Add(
			text.NewCol(12, "Generated by Trivy Plugin | "+currentTime, props.Text{
				Align: align.Right,
				Size:  7,
				Color: ColorLightGray,
				Style: fontstyle.Italic,
			}),
		),
	)

	// --- Result Iteration ---
	for _, result := range report.Results {
		// Sorting logic: Severity (Critical -> Low) then Package Name
		sort.Slice(result.Vulnerabilities, func(i, j int) bool {
			v1 := result.Vulnerabilities[i]
			v2 := result.Vulnerabilities[j]
			w1 := getSeverityWeight(v1.Severity)
			w2 := getSeverityWeight(v2.Severity)
			if w1 != w2 {
				return w1 > w2
			}
			return v1.PkgName < v2.PkgName
		})

		fullTargetInfo := fmt.Sprintf("Target: %s (%s)", result.Target, result.Class)
		
		// Target Name Row
		m.AddRows(
			row.New(15).Add(
				text.NewCol(12, fullTargetInfo, props.Text{
					Top:    2,
					Style:  fontstyle.Bold,
					Size:   10,
					Family: fontfamily.Arial,
					Color:  ColorDarkGray,
					Align:  align.Left,
				}),
			),
		)

		// Table Header Row
		headerRow := row.New(8)
		headerRow.WithStyle(&props.Cell{BackgroundColor: ColorBgHeader})
		for i, h := range headers {
			headerRow.Add(text.NewCol(colWidths[i], h, headerProp))
		}
		m.AddRows(headerRow)

		if len(result.Vulnerabilities) == 0 {
			m.AddRows(
				text.NewRow(8, "No vulnerabilities found.", props.Text{
					Style:  fontstyle.Italic,
					Align:  align.Center,
					Family: fontfamily.Arial,
					Color:  ColorBodyText,
					Size:   8,
				}),
			)
		} else {
			for _, vuln := range result.Vulnerabilities {
				displayTitle := strings.ReplaceAll(vuln.Title, "\n", " ")
				
				// Calculate dynamic row height based on content length
				rowHeight := calculateRowHeight(len(vuln.PkgName), len(displayTitle))

				r := row.New(rowHeight)
				
				bgColor := getBackgroundColor(vuln.Severity)
				r.WithStyle(&props.Cell{BackgroundColor: bgColor})

				sevProp := bodyProp
				sevProp.Style = fontstyle.Bold
				sevProp.Color = getSeverityColor(vuln.Severity)
				sevProp.Align = align.Center

				fixedVer := vuln.FixedVersion
				if fixedVer == "" {
					fixedVer = "-"
				}

				r.Add(
					text.NewCol(colWidths[0], vuln.VulnerabilityID, bodyProp),
					text.NewCol(colWidths[1], vuln.Severity, sevProp),
					text.NewCol(colWidths[2], vuln.PkgName, bodyProp),
					text.NewCol(colWidths[3], vuln.InstalledVersion, bodyProp),
					text.NewCol(colWidths[4], fixedVer, bodyProp),
					text.NewCol(colWidths[5], displayTitle, bodyProp),
				)
				m.AddRows(r)
			}
		}
		
		// Separator Line
		m.AddRows(
			line.NewRow(1.0, props.Line{Color: &props.Color{Red: 200, Green: 200, Blue: 200}}),
			row.New(8), // Bottom spacer
		)
	}

	document, err := m.Generate()
	if err != nil {
		return err
	}
	return document.Save(path)
}