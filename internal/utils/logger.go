package utils

import (
	"fmt"
)

// ANSI color codes
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	White  = "\033[37m"
)

func LogInfo(format string, args ...interface{}) {
	fmt.Printf(Blue+"[INFO] "+Reset+format+"\n", args...)
}

func LogSuccess(format string, args ...interface{}) {
	fmt.Printf(Green+"[SUCCESS] "+Reset+format+"\n", args...)
}

func LogWarning(format string, args ...interface{}) {
	fmt.Printf(Yellow+"[WARN] "+Reset+format+"\n", args...)
}

func LogError(format string, args ...interface{}) {
	fmt.Printf(Red+"[ERROR] "+Reset+format+"\n", args...)
}

func PrintBanner() {
	// Bold Red
	BoldRed := "\033[1;31m"
	// Dim/Dark (for shadow effect)
	Dark := "\033[90m"

	banner := `
    ██╗  ██╗ ██████╗ ██████╗      ██████╗  ██████╗  █████╗ ████████╗
    ██║  ██║██╔═══██╗╚════██╗    ██╔════╝ ██╔═══██╗██╔══██╗╚══██╔══╝
    ███████║██║   ██║ █████╔╝    ██║  ███╗██║   ██║███████║   ██║   
    ╚════██║██║   ██║ ╚═══██╗    ██║   ██║██║   ██║██╔══██║   ██║   
         ██║╚██████╔╝██████╔╝    ╚██████╔╝╚██████╔╝██║  ██║   ██║   
         ╚═╝ ╚═════╝ ╚═════╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
`
	fmt.Println(BoldRed + banner + Reset)
	fmt.Println(Dark + "    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + Reset)
	fmt.Println(Red + "                    🐐 403 Bypass Tool v2.0.0" + Reset)
	fmt.Println(Dark + "    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" + Reset)
	fmt.Println(White + "                         Author: " + Red + "XBug0" + Reset)
	fmt.Println()
}
