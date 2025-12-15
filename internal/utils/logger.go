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
	BoldRed := "\033[1;31m"
	BoldWhite := "\033[1;37m"

	fmt.Println()
	fmt.Println(BoldRed + "    __ __  ____  _____  __________  ___  ______" + Reset)
	fmt.Println(BoldRed + "   / // / / __ \\/__  / / ____/ __ \\/   |/_  __/" + Reset)
	fmt.Println(BoldRed + "  / // /_/ / / /  / / / / __/ / / / /| | / /   " + Reset)
	fmt.Println(BoldRed + " /__  __/ /_/ /  / /__/ /_/ / /_/ / ___ |/ /    " + Reset)
	fmt.Println(BoldRed + "   /_/  \\____/  /____/\\____/\\____/_/  |_/_/     " + Reset)
	fmt.Println()
	fmt.Println(BoldWhite + "  ================================================" + Reset)
	fmt.Println(BoldWhite + "           403 Bypass Scanner v2.0.0" + Reset)
	fmt.Println(BoldWhite + "  ================================================" + Reset)
	fmt.Println(BoldRed + "                  Author: XBug0" + Reset)
	fmt.Println()
}
