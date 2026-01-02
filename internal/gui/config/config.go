// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package config

import (
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config holds the configuration for the Pola GUI server
type Config struct {
	ServerPort    int
	PoladAddress  string
	LogLevel      string
	AllowedOrigin string
}

// YAMLConfig represents the YAML configuration file structure
type YAMLConfig struct {
	Server struct {
		Port int `yaml:"port"`
	} `yaml:"server"`
	Polad struct {
		Address string `yaml:"address"`
	} `yaml:"polad"`
	AllowedOrigin string `yaml:"allowed_origin"`
}

// Load loads configuration from environment variables with defaults
func Load() *Config {
	return &Config{
		ServerPort:    getEnvAsInt("POLA_GUI_PORT", 8080),
		PoladAddress:  getEnv("POLAD_GRPC_ADDRESS", "127.0.0.1:50052"),
		LogLevel:      getEnv("LOG_LEVEL", "info"),
		AllowedOrigin: getEnv("ALLOWED_ORIGIN", "http://localhost:5173"),
	}
}

// LoadFromFile loads configuration from a YAML file
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var yamlCfg YAMLConfig
	if err := yaml.Unmarshal(data, &yamlCfg); err != nil {
		return nil, err
	}

	cfg := &Config{
		ServerPort:    yamlCfg.Server.Port,
		PoladAddress:  yamlCfg.Polad.Address,
		LogLevel:      "info",
		AllowedOrigin: yamlCfg.AllowedOrigin,
	}

	// Environment variables override file config
	if port := os.Getenv("POLA_GUI_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cfg.ServerPort = p
		}
	}
	if addr := os.Getenv("POLAD_GRPC_ADDRESS"); addr != "" {
		cfg.PoladAddress = addr
	}
	if origin := os.Getenv("ALLOWED_ORIGIN"); origin != "" {
		cfg.AllowedOrigin = origin
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}
