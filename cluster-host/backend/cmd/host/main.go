package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cluster-backend/internal/api"
	"cluster-backend/internal/config"
	"cluster-backend/internal/repository"
	"cluster-backend/internal/service"
	"cluster-backend/internal/worker"
)

func main() {
	log.Println("🚀 Starting Cluster Monitor Host Backend...")

	// 1. Load configuration
	cfg := config.Load()

	// 2. Initialize Database & Cache Repositories
	pgDB, err := repository.NewPostgres(cfg)
	if err != nil {
		log.Fatalf("Fatal: Database initialization failed: %v", err)
	}

	redisRepo, err := repository.NewRedis(cfg)
	if err != nil {
		log.Printf("Warning: Redis initialization returned error: %v", err)
	}

	// 3. Initialize Domain Services & Worker Pool
	workerPool := worker.NewWorkerPool(pgDB.DB, redisRepo, cfg.EncryptionKey)
	alertService := service.NewAlertService(pgDB.DB, redisRepo, cfg)
	apiHandler := api.NewAPIHandler(pgDB.DB, redisRepo, cfg)

	// 4. Start Background Engines
	workerPool.Start()
	alertService.StartAlertingLoop()
	alertService.StartMetricsPruningLoop()

	// 5. Construct Router & HTTP Server
	router := api.NewRouter(apiHandler)
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 6. Graceful Shutdown Setup
	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("Server listening on port %s...", cfg.Port)
		serverErrors <- srv.ListenAndServe()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		log.Fatalf("Error starting HTTP server: %v", err)

	case sig := <-shutdown:
		log.Printf("Received signal %v. Initiating graceful shutdown...", sig)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
			_ = srv.Close()
		}

		_ = pgDB.DB.Close()
		if redisRepo != nil && redisRepo.Client != nil {
			_ = redisRepo.Client.Close()
		}
		log.Println("Host backend stopped cleanly.")
	}
}
