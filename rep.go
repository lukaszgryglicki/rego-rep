package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	gSHAs  = "./rego_shas.txt"
	gTimes = "./rego_times.txt"
)

func rep() error {
	warn := os.Getenv("WARN") != ""
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
		// 5d8bceaffa4a3368d14cc2d321cdd2fad5ffb1c94ee2c05119c3053758bed4ebeffa8eb260699c437c9db34ef3e024150aa2c6ec953882b45bf8bd4c17292c24  ./envoyproxy/archive/docs/envoy/v1.21.3/_downloads/820c9994319e32174253485940818917/policy.rego
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
		if warn && len(v) > 1 {
			fmt.Printf("SHA '%s' matches multiple files: %+v\n", k, v)
		}
	}
	timesf, err := os.Open(times)
	if err != nil {
		return err
	}
	defer timesf.Close()
	timess := bufio.NewScanner(timesf)
	years := make(map[string]map[string]struct{})
	for timess.Scan() {
		line := timess.Text()
		// -rw-r--r-- 1 root root 232 2023 ./envoyproxy/archive/docs/envoy/v1.24.2/_downloads/820c9994319e32174253485940818917/policy.rego
		ary := strings.Fields(line)
		year := ary[5]
		yeari, err := strconv.Atoi(year)
		if err != nil {
			fmt.Printf("incorrect year value: '%s'\n", year)
			continue
		}
		if yeari < 2000 || yeari > time.Now().Year() {
			fmt.Printf("incorrect year value: '%s' -> %d\n", year, yeari)
			continue
		}
		fn := strings.Join(ary[6:], " ")
		mp, ok := shasm1[fn]
		if !ok {
			fmt.Printf("there is no SHA value for '%s' file (year %s)\n", fn, year)
			continue
		}
		var sha string
		for v := range mp {
			sha = v
			break
		}
		_, ok = years[year]
		if !ok {
			years[year] = make(map[string]struct{})
		}
		years[year][sha] = struct{}{}
	}
	err = timess.Err()
	if err != nil {
		return err
	}
	// fmt.Printf("%+v\n", years)
	yearss := []string{}
	for year := range years {
		yearss = append(yearss, year)
	}
	sort.Strings(yearss)
	fmt.Printf("year,\"rego files\"\n")
	for _, year := range yearss {
		shas, ok := years[year]
		if !ok {
			fmt.Printf("year %s not present in map +%v\n", year, years)
			continue
		}
		fmt.Printf("%s,%d\n", year, len(shas))
	}
	return nil
}

func main() {
	err := rep()
	if err != nil {
		panic(err)
	}
}
