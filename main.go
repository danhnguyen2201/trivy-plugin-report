package main

import (
	"encoding/json"
	"os"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/spf13/cobra"
    
    // Replace with your actual module path from go.mod
	"trivy-plugin-excel/pkg/excel" 
)

func main() {
	var output string
	var beautify bool

	var rootCmd = &cobra.Command{
		Use:   "excel-report",
		Short: "Trivy plugin to export scan results to Excel",
		Long:  "A plugin that reads Trivy JSON output from stdin and generates a formatted Excel report.",
		Run: func(cmd *cobra.Command, args []string) {
			var report types.Report
			// Standard Plugin Principle: Read from Stdin
			if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
				log.Logger.Fatal("Error: Plugin requires Trivy JSON input via stdin. Usage: trivy image -f json <target> | trivy excel-report run")
			}

			log.Logger.Infof("Generating Excel report at: %s", output)
			if err := excel.Export(&report, output, beautify); err != nil {
				log.Logger.Fatalf("Failed to export Excel file: %v", err)
			}
			log.Logger.Info("Report generated successfully!")
		},
	}

	rootCmd.Flags().StringVarP(&output, "output", "o", "trivy-report.xlsx", "Path to output file")
	rootCmd.Flags().BoolVarP(&beautify, "beautify", "b", true, "Enable severity background coloring")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}