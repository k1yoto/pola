// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/nttcom/pola/internal/gui/client"
	"github.com/nttcom/pola/internal/gui/config"
	"github.com/nttcom/pola/internal/gui/handlers"
	"go.uber.org/zap"
)

//go:embed web/dist
var webFS embed.FS

func main() {
	// Parse command line flags
	configFile := flag.String("f", "", "Path to configuration file (YAML)")
	flag.Parse()

	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// Load configuration
	var cfg *config.Config
	if *configFile != "" {
		cfg, err = config.LoadFromFile(*configFile)
		if err != nil {
			logger.Fatal("Failed to load config file", zap.String("file", *configFile), zap.Error(err))
		}
		logger.Info("Loaded configuration from file", zap.String("file", *configFile))
	} else {
		cfg = config.Load()
		logger.Info("Loaded configuration from environment variables")
	}

	logger.Info("Pola GUI Server starting",
		zap.String("version", "0.1.0"),
		zap.Int("port", cfg.ServerPort),
		zap.String("polad_address", cfg.PoladAddress),
	)

	// Initialize gRPC client with retry
	grpcClient, err := client.NewClient(cfg.PoladAddress, logger)
	if err != nil {
		logger.Fatal("Failed to connect to polad", zap.Error(err))
	}
	defer grpcClient.Close()

	// Initialize Gin router
	router := gin.New()

	// Disable automatic redirects
	router.RedirectTrailingSlash = false
	router.RedirectFixedPath = false

	// Add middlewares
	router.Use(loggingMiddleware(logger))
	router.Use(gin.Recovery())
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{cfg.AllowedOrigin},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Static files (React frontend)
	distFS, err := fs.Sub(webFS, "web/dist")
	if err != nil {
		logger.Fatal("Failed to access embedded frontend", zap.Error(err))
	}

	// Serve root path and static files BEFORE API routes
	router.GET("/", func(c *gin.Context) {
		// Read index.html from embedded FS
		data, err := fs.ReadFile(distFS, "index.html")
		if err != nil {
			logger.Error("Failed to read index.html", zap.Error(err))
			c.String(http.StatusInternalServerError, "Failed to load page")
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	})

	// Serve static assets
	router.GET("/assets/*filepath", func(c *gin.Context) {
		filepath := c.Param("filepath")
		// Remove leading slash
		if len(filepath) > 0 && filepath[0] == '/' {
			filepath = filepath[1:]
		}
		c.FileFromFS("assets/"+filepath, http.FS(distFS))
	})

	// API routes
	api := router.Group("/api")
	{
		api.GET("/sessions", handlers.GetSessions(grpcClient.GetClient(), logger))
		api.GET("/ted", handlers.GetTED(grpcClient.GetClient(), logger))
		api.GET("/policies", handlers.GetPolicies(grpcClient.GetClient(), logger))
		api.POST("/policies", handlers.CreatePolicy(grpcClient.GetClient(), logger))
		api.DELETE("/policies", handlers.DeletePolicy(grpcClient.GetClient(), logger))
	}

	// Fallback to index.html for SPA routing (for non-API, non-assets routes)
	router.NoRoute(func(c *gin.Context) {
		data, err := fs.ReadFile(distFS, "index.html")
		if err != nil {
			logger.Error("Failed to read index.html", zap.Error(err))
			c.String(http.StatusNotFound, "Page not found")
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	})

	// Create HTTP server
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.ServerPort),
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("Starting HTTP server", zap.Int("port", cfg.ServerPort))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", zap.Error(err))
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", zap.Error(err))
	}

	logger.Info("Pola GUI Server stopped")
}

// loggingMiddleware logs HTTP requests
func loggingMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		logger.Info("HTTP request",
			zap.String("method", c.Request.Method),
			zap.String("path", path),
			zap.String("query", query),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", c.ClientIP()),
		)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
