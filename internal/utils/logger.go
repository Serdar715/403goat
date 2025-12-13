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
	banner := `
  _  _    ___    ____                      _   
 | || |  / _ \  |___ \    __ _    ___     / \        _   
 | || |_| | | |   __) |  / _' |  / _ \   / _ \     _| |_ 
 |__   _| |_| |  / __/  | (_| | | (_) | / ___ \   |_   _|
    |_|  \___/  |_____|  \__, |  \___/ /_/   \_\    |_|  
                         |___/                           
	`
	fmt.Println(Cyan + banner + Reset)
	fmt.Println(White + "    403 Bypass Tool - 403goat" + Reset)
	fmt.Println(White + "    v1.0.0 - Professional Edition" + Reset)
	fmt.Println()
}
