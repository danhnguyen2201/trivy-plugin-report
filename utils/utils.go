package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"
)

var (
	// VulnStatuses maps Trivy status codes to English descriptions
	VulnStatuses = map[string]string{
		"not_affected":        "Software is not affected by the vulnerability on this platform.",
		"affected":            "Software is affected, but no patch is available yet.",
		"fixed":               "A patch has been released for this software.",
		"under_investigation": "Vulnerability status is currently being investigated.",
		"will_not_fix":        "Software is affected, but there are currently no plans to fix it.",
		"fix_deferred":        "Software is affected, and a fix may be released in the future.",
		"end_of_life":         "Software is EOL; no further vulnerability analysis will be performed.",
	}

	// SeverityLabels provides a mapping for severity display
	SeverityLabels = map[string]string{
		"CRITICAL": "Critical",
		"HIGH":     "High",
		"MEDIUM":   "Medium",
		"LOW":      "Low",
		"UNKNOWN":  "Unknown",
	}
)

// FormatTime converts a time object to a standard English string format
func FormatTime(t *time.Time) string {
	if t == nil {
		return "N/A"
	}
	// Using UTC for international reporting consistency
	return t.UTC().Format("Jan 02, 2006 15:04:05 UTC")
}

// ReadJSONFromFile reads and parses a Trivy JSON report from a local file
func ReadJSONFromFile(filename string) (*types.Report, error) {
	if filepath.Ext(filename) != ".json" {
		log.Logger.Debugf("%s is not a JSON file", filename)
		return nil, nil
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, xerrors.Errorf("failed to read file: %w", err)
	}

	var report types.Report
	if err = json.Unmarshal(data, &report); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal JSON: %w", err)
	}
	return &report, nil
}

// Sort transforms a map into a sorted 2D slice based on values (descending)
func Sort(data map[string]int) [][]string {
	var items []struct {
		Key   string
		Value int
	}

	for k, v := range data {
		items = append(items, struct {
			Key   string
			Value int
		}{Key: k, Value: v})
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Value > items[j].Value
	})

	result := make([][]string, len(items))
	for i, item := range items {
		result[i] = []string{item.Key, strconv.Itoa(item.Value)}
	}

	return result
}

// SetArtifactType returns a human-readable English string for the artifact type
func SetArtifactType(at artifact.Type) string {
	if at == artifact.TypeContainerImage {
		return "Container Image"
	}
	if at == artifact.TypeFilesystem {
		return "Filesystem"
	}
	return string(at)
}

// SetResultClass returns a human-readable English string for the result class
func SetResultClass(rc types.ResultClass) string {
	switch rc {
	case types.ClassOSPkg:
		return "OS Packages"
	case types.ClassLangPkg:
		return "Language Packages"
	case types.ClassConfig:
		return "Configuration"
	default:
		return string(rc)
	}
}