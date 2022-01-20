/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
	"gopkg.in/xmlpath.v2"
)

func getSummaryValue(reportPath string, severity string) int {

	report, err := os.Open(reportPath)
	if err != nil {
		log.Fatal(err)
	}

	var severityValue int
	path := xmlpath.MustCompile(`//tr[.//td[@class="` + severity + `"]]/td[2]/div/text()`)
	root, err := xmlpath.Parse(report)
	if err != nil {
		log.Fatal(err)
	}
	if value, ok := path.String(root); ok {
		i, err := strconv.Atoi(value)
		if err != nil {
			log.Fatal(err)
		}
		severityValue = i
	}
	return severityValue
}

// checkCmd represents the check command
var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "checks a generated OWASP ZAP report against a custom quality gate criteria",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

		reportPath, _ := cmd.Flags().GetString("report")

		maxHigh, _ := cmd.Flags().GetInt("max-high")
		maxMedium, _ := cmd.Flags().GetInt("max-medium")
		maxLow, _ := cmd.Flags().GetInt("max-low")
		maxInfo, _ := cmd.Flags().GetInt("max-info")
		maxFP, _ := cmd.Flags().GetInt("max-fp")

		var high int = getSummaryValue(reportPath, "risk-3")
		var medium int = getSummaryValue(reportPath, "risk-2")
		var low int = getSummaryValue(reportPath, "risk-1")
		var informational int = getSummaryValue(reportPath, "risk-0")
		var falsePositives int = getSummaryValue(reportPath, "risk--1")

		fmt.Println("high\t" + strconv.FormatInt(int64(high), 10))
		fmt.Println("medium\t" + strconv.FormatInt(int64(medium), 10))
		fmt.Println("low\t" + strconv.FormatInt(int64(low), 10))
		fmt.Println("informational\t" + strconv.FormatInt(int64(informational), 10))
		fmt.Println("falsePositives\t" + strconv.FormatInt(int64(falsePositives), 10))

		if high > maxHigh {
			log.Fatal("Max High Alerts: " + strconv.Itoa(maxHigh) + "\tReported High Alerts: " + strconv.FormatInt(int64(high), 10))
		}
		if medium > maxMedium {
			log.Fatal("Max Medium Alerts: " + strconv.Itoa(maxMedium) + "\tReported Medium Alerts: " + strconv.FormatInt(int64(medium), 10))
		}
		if low > maxLow {
			log.Fatal("Max Low Alerts: " + strconv.Itoa(maxLow) + "\tReported Low Alerts: " + strconv.FormatInt(int64(low), 10))
		}
		if informational > maxInfo {
			log.Fatal("Max Informational Alerts: " + strconv.Itoa(maxInfo) + "\tReported Informational Alerts: " + strconv.FormatInt(int64(informational), 10))
		}
		if falsePositives > maxFP {
			log.Fatal("Max False Positive Alerts: " + strconv.Itoa(maxFP) + "\tReported False Positive Alerts: " + strconv.FormatInt(int64(falsePositives), 10))
		}

		log.Println("Passed all quality gate criteria for OWASP ZAP Report")

	},
}

func init() {
	rootCmd.AddCommand(checkCmd)

	checkCmd.PersistentFlags().StringP("report", "r", "", "absolute path to the OWASP ZAP HTML report")

	checkCmd.PersistentFlags().Int("max-high", 0, "maximum number of High alerts allowed (default 0)")
	checkCmd.PersistentFlags().Int("max-medium", 2, "maximum number of Medium alerts allowed")
	checkCmd.PersistentFlags().Int("max-low", 5, "maximum number of Low alerts allowed")
	checkCmd.PersistentFlags().Int("max-info", 10, "maximum number of Informational alerts allowed")
	checkCmd.PersistentFlags().Int("max-fp", 5, "maximum number of False Positive alerts allowed")

	checkCmd.MarkPersistentFlagRequired("report")
}
