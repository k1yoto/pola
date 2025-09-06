// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/nttcom/pola/internal/config"
	"github.com/nttcom/pola/internal/pkg/gobgp"
	"github.com/nttcom/pola/internal/pkg/table"
	"github.com/nttcom/pola/internal/pkg/version"
	"github.com/nttcom/pola/pkg/logger"
	"github.com/nttcom/pola/pkg/server"
)

const TEDUpdateInterval = 10 // (min)

type flags struct {
	configFile string
}

func main() {
	// Check if --version flag was passed
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("polad " + version.Version())
		return
	}

	// Parse flags
	f := &flags{}
	flag.StringVar(&f.configFile, "f", "polad.yaml", "Specify a configuration file")
	flag.Parse()

	// Read configuration file
	c, err := config.ReadConfigFile(f.configFile)
	if err != nil {
		log.Panicf("failed to read config file: %v", err)
	}

	// Create log directory if it does not exist
	if err := os.MkdirAll(c.Global.Log.Path, 0755); err != nil {
		log.Panicf("failed to create log directory: %v", err)
	}

	// Open log file
	fp, err := os.OpenFile(c.Global.Log.Path+c.Global.Log.Name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Panicf("failed to open log file: %v", err)
	}
	defer func() {
		if err := fp.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close log file \"%s\": %v\n", c.Global.Log.Path+c.Global.Log.Name, err)
		}
	}()

	// Initialize logger
	logger := logger.LogInit(fp, c.Global.Log.Debug)
	defer func() {
		if err := logger.Sync(); err != nil {
			logger.Panic("Failed to sync logger", zap.Error(err))
			log.Panicf("failed to sync logger: %v", err)
		}
	}()

	// Prepare TED update tools for TED-enabled modes
	var tedElemsChan chan []table.TEDElem
	mode := server.PCEMode(c.Global.Mode)

	// Create unified options
	o := &server.CommonOptions{
		Mode:           mode,
		PCEPServerAddr: c.Global.PCEPServer.Address,
		PCEPServerPort: c.Global.PCEPServer.Port,
		PCEPClientAddr: c.Global.PCEPClient.Address,
		PCEPClientPort: c.Global.PCEPClient.Port,
		GRPCAddr:       c.Global.GRPCServer.Address,
		GRPCPort:       c.Global.GRPCServer.Port,
		USidMode:       c.Global.USidMode,
		DomainID:       c.Global.DomainID,
	}

	if c.Global.TED != nil && c.Global.TED.Enable && (mode == server.ModePCE || mode == server.ModeParentPCE || mode == server.ModeChildPCE) {
		o.TEDEnable = c.Global.TED.Enable
		switch c.Global.TED.Source {
		case "gobgp":
			tedElemsChan = startGoBGPUpdate(&c, logger)
			if tedElemsChan == nil {
				logger.Panic("GoBGP update channel is nil")
				log.Panic("GoBGP update channel is nil")
			}
		default:
			logger.Panic("Specified TED source is not defined")
			log.Panic("specified TED source is not defined")
		}
	}

	// Validate mode
	switch mode {
	case server.ModePCC, server.ModePCE, server.ModeChildPCE, server.ModeParentPCE:
		// Start unified PCE server
		if serverErr := server.NewPCEServer(o, logger, tedElemsChan); serverErr.Error != nil {
			log.Panicf("failed to start PCE server (mode: %s): %v", mode, serverErr.Error)
		}
	default:
		logger.Panic("Invalid mode specified", zap.String("mode", c.Global.Mode))
		log.Panicf("invalid mode specified: %s", c.Global.Mode)
	}
}

func startGoBGPUpdate(c *config.Config, logger *zap.Logger) chan []table.TEDElem {
	if c.Global.TED == nil {
		logger.Error("TED does not exist")
		return nil
	}
	tedElemsChan := make(chan []table.TEDElem)

	go func() {
		for {
			tedElems, err := gobgp.GetBGPlsNLRIs(c.Global.GoBGP.GRPCClient.Address, c.Global.GoBGP.GRPCClient.Port)
			logger.Debug("Request TED update", zap.String("source", "GoBGP"), zap.String("session", c.Global.GoBGP.GRPCClient.Address+":"+c.Global.GoBGP.GRPCClient.Port))
			if err != nil {
				logger.Error("Failed session with GoBGP", zap.Error(err))
			} else {
				tedElemsChan <- tedElems
			}
			time.Sleep(TEDUpdateInterval * time.Minute)
		}
	}()

	return tedElemsChan
}
