package utils

import (
	"fmt"

	"github.com/fatih/color"
)

var (
	infoPrefix    = color.New(color.FgBlue).SprintFunc()
	successPrefix = color.New(color.FgGreen).SprintFunc()
	warnPrefix    = color.New(color.FgYellow).SprintFunc()
	errorPrefix   = color.New(color.FgRed).SprintFunc()
	bannerColor   = color.New(color.FgHiRed, color.Bold).SprintFunc()
	whiteBold     = color.New(color.FgHiWhite, color.Bold).SprintFunc()
)

func LogInfo(format string, args ...interface{}) {
	fmt.Printf("%s %s\n", infoPrefix("[INFO]"), fmt.Sprintf(format, args...))
}

func LogSuccess(format string, args ...interface{}) {
	fmt.Printf("%s %s\n", successPrefix("[SUCCESS]"), fmt.Sprintf(format, args...))
}

func LogWarning(format string, args ...interface{}) {
	fmt.Printf("%s %s\n", warnPrefix("[WARN]"), fmt.Sprintf(format, args...))
}

func LogError(format string, args ...interface{}) {
	fmt.Printf("%s %s\n", errorPrefix("[ERROR]"), fmt.Sprintf(format, args...))
}

func PrintBanner() {
	fmt.Println()
	fmt.Println(bannerColor(`   _  _    ___  _____    ____  ___    _  _____`))
	fmt.Println(bannerColor(`  | || |  / _ \|___ /   / ___|/ _ \  / \|_   _|`))
	fmt.Println(bannerColor(`  | || |_| | | | _ \  | |  _| | | |/ _ \ | |  `))
	fmt.Println(bannerColor(`  |__   _| |_| | __) | | |_| | |_| / ___ \| |  `))
	fmt.Println(bannerColor(`     |_|  \___/|____/   \____|\___/_/   \_\_|  `))
	fmt.Println()
	fmt.Println(whiteBold("  ================================================"))
	fmt.Println(whiteBold("           403 Bypass Scanner v2.0.0"))
	fmt.Println(whiteBold("  ================================================"))
	fmt.Println(bannerColor("                  Author: XBug0"))
	fmt.Println()
}
