package main

import (
	"bufio"
	"config_analyze/internal/processor/vulnerability"
	"config_analyze/internal/server/http"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

func main() {
	http.New().Start(8080)
	configPath := flag.String("config", "../../example/config1.json", "Path to configuration file")
	silent := flag.Bool("silent", false, "Silent mode")
	stdin := flag.Bool("stdin", false, "Stdin mode")
	flag.Parse()
	if *configPath == "" && !*stdin {
		log.Fatal("no file provided")
	}
	var data []byte
	var err error
	if *stdin {
		data, err = readFromStdinWithMarker("CONFIG_END")
		if err != nil {
			log.Fatal(err)
		}
	} else {
		data, err = os.ReadFile(*configPath) //"../../example/config1.yaml") //args[0]) //
		if err != nil {
			log.Fatal(err)
		}
	}
	res, err := vulnerability.New().Process(data)
	if err != nil {
		log.Fatal(err)
	}
	if len(res) > 0 {
		fmt.Println(string(res))
		if *silent {
			os.Exit(0)
		}
		os.Exit(1)
	}
}

func readFromStdinWithMarker(marker string) ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	var lines []string

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == marker {
			break
		}

		lines = append(lines, line)

		if err == io.EOF {
			break
		}
	}

	return []byte(strings.Join(lines, "")), nil
}
