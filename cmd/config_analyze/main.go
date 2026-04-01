package main

import (
	"config_analyze/internal/domain"
	"config_analyze/internal/processor/vulnerability"
	"config_analyze/internal/server/grpc"
	"config_analyze/internal/server/http"
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var mapConfig = map[string]domain.Field{
	"debug_mode":   domain.DebugMode{},
	"debug":        domain.DebugMode{},
	"log_level":    domain.LogLevel{},
	"password":     domain.Password{},
	"secret":       domain.Password{},
	"api_key":      domain.Password{},
	"bind_address": domain.Host{},
	"listen_addr":  domain.Host{},
	"host":         domain.Host{},
	"tls_enabled":  domain.Safety{},
	"ssl_enabled":  domain.Safety{},
	"use_ssl":      domain.Safety{},
	"algorithm":    domain.Algorithm{},
	"encryption":   domain.Algorithm{},
	"cipher":       domain.Algorithm{},
}

func main() {
	silent := flag.Bool("s", false, "Silent mode")
	silentLong := flag.Bool("silent", false, "Silent mode Long")
	stdin := flag.Bool("stdin", false, "Stdin mode")
	httpServerMode := flag.Bool("http", false, "HTTP server")
	httpPort := flag.Int("http-port", 8080, "HTTP port")
	grpcServerMode := flag.Bool("grpc", false, "GRPC server")
	grpcPort := flag.Int("grpc-port", 8000, "GRPC port")
	flag.Parse()

	if *silentLong {
		*silent = true
	}

	serverMode := *httpServerMode || *grpcServerMode
	if len(flag.Args()) < 1 && !serverMode {
		log.Fatal("no file provided")
	}

	processor := vulnerability.New(mapConfig)

	if serverMode {
		wg := sync.WaitGroup{}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()

		var httpServer *http.Server
		var grpcServer *grpc.Server
		if *httpServerMode {
			httpServer = http.New(processor)
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := httpServer.Start(*httpPort)
				if err != nil {
					log.Println(err)
					cancel()
				}
			}()
		}
		if *grpcServerMode {
			grpcServer = grpc.New(processor)
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := grpcServer.Start(*grpcPort)
				if err != nil {
					log.Println(err)
					cancel()
				}

			}()
		}
		<-ctx.Done()
		log.Println("Shutting down servers...")
		if *grpcServerMode {
			grpcServer.Stop()
		}
		if *httpServerMode {
			err := httpServer.Stop()
			if err != nil {
				log.Fatal(err)
			}
		}
		wg.Wait()
		return
	}

	var configPath string
	if len(flag.Args()) > 0 {
		configPath = flag.Args()[0] //flag.String("config", "../../example/config1.json", "Path to configuration file")
	}

	hasErr, err := processor.StartRead(configPath, *stdin)
	if err != nil {
		log.Fatal(err)
	}
	if hasErr {
		if *silent {
			os.Exit(0)
		}
		os.Exit(1)
	}
}
