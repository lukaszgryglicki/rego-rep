package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
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
	shasf, err := os.Open(shas)
	if err != nil {
		return err
	}
	defer shasf.Close()
	shass := bufio.NewScanner(shasf)
	shasm1 := make(map[string]map[string]struct{})
	shasm2 := make(map[string]map[string]struct{})
	for shass.Scan() {
		line := shass.Text()
		ary := strings.Fields(line)
		sha := ary[0]
		fn := strings.Join(ary[1:], " ")
		_, ok := shasm1[fn]
		if !ok {
			shasm1[fn] = make(map[string]struct{})
		}
		shasm1[fn][sha] = struct{}{}
		_, ok = shasm2[sha]
		if !ok {
			shasm2[sha] = make(map[string]struct{})
		}
		shasm2[sha][fn] = struct{}{}
	}
	err = shass.Err()
	if err != nil {
		return err
	}
	for k, v := range shasm1 {
		if len(v) > 1 {
			fmt.Printf("file '%s' has multiple SHAs: %+v\n", k, v)
		}
	}
	for k, v := range shasm2 {
		if len(v) > 1 {
			fmt.Printf("SHA '%s' matches multiple files: %+v\n", k, v)
		}
	}
	return nil
}

func main() {
	err := rep()
	if err != nil {
		panic(err)
	}
}
