package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"go.ssnk.in/joustlm/internal"
)

var (
	DEFAULT_CONFIG_PATH = func() string {
		if path := os.Getenv("CONFIG_PATH"); path != "" {
			return path
		}
		return "config/config.yml"
	}()

	CONFIG_PATH = flag.String("config", DEFAULT_CONFIG_PATH, "Path to application config")
)

func main() {
	flag.Parse()

	if len(*CONFIG_PATH) == 0 {
		log.Fatalf("CONFIG_PATH is required")
	}
	core := internal.GetInstance().
		WithConfig(*CONFIG_PATH).
		WithLogger().
		WithDao().
		WithAuth().
		WithService().
		WithHandler().
		WithServer()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		if err := core.Start(); err != nil {
			log.Fatal("Server failed to start:", err)
		}
	}()
	<-sigChan
	log.Println("Shutting down gracefully...")
	core.Cleanup()
}
