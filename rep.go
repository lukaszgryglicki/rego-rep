package main

import (
	"os"
)

const (
	gSHAs  = "./rego_shas.txt"
	gTimes = "./rego_times.txt"
)

func rep() error {
	shas := os.Getenv("SHAS")
	if shas == "" {
		shas = gSHAs
	}
	times := os.Getenv("TIMES")
	if times == "" {
		times = gTimes
	}
	return nil
}

func main() {
	err := rep()
	if err != nil {
		panic(err)
	}
}
