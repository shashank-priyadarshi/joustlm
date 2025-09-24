package internal

import (
	"errors"
	"log"
	"sync"

	"go.ssnk.in/joustlm/config"
	"go.ssnk.in/joustlm/logger"
)

type Core struct {
	mu      sync.RWMutex
	config  *config.Config
	logger  *logger.Logger
	llm     *LLM
	dao     *Dao
	service *Service
	handler *Handler
	server  *Server
}

var (
	instance *Core
	once     sync.Once

	ErrConfigRequired   = errors.New("configuration is required")
	ErrLoggerRequired   = errors.New("logger is required")
	ErrDatabaseRequired = errors.New("database connection is required")
	ErrAuthRequired     = errors.New("auth service is required")
	ErrHandlerRequired  = errors.New("handler is required")
	ErrServerRequired   = errors.New("server is required")
)

func GetInstance() *Core {
	once.Do(func() {
		instance = &Core{}
	})
	return instance
}

func (c *Core) WithConfig(configPath string) *Core {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Printf("Failed to load configuration: %v", err)
		return c
	}

	c.SetConfig(cfg)
	return c
}

func (c *Core) WithLogger() *Core {
	if c.config == nil {
		log.Printf("Warning: Cannot initialize logger without configuration")
		return c
	}

	logger := logger.New(
		logger.SetLevel(logger.Level(c.config.Server.Logging.Level)),
		logger.SetFormat(logger.Format(c.config.Server.Logging.Format)),
		logger.SetConfig(&c.config.Server.Logging),
		logger.SetCaller(config.Backend),
	)

	logger.Info("Config loaded")
	logger.Info("Logger initialized", "level", c.config.Server.Logging.Level, "format", c.config.Server.Logging.Format)
	logger.Info("Starting server")

	c.SetLogger(&logger)
	return c
}

func (c *Core) WithLLM() *Core {
	if c.config == nil {
		log.Printf("Warning: Cannot initialize LLM without configuration")
		return c
	}

	if c.logger == nil {
		log.Printf("Warning: Cannot initialize LLM without logger")
		return c
	}

	llm := NewLLM(&c.config.Server.LLM)
	c.SetLLM(llm)
	return c
}

func (c *Core) WithDao() *Core {
	if c.config == nil {
		log.Printf("Warning: Cannot initialize database without configuration")
		return c
	}

	if c.logger == nil {
		log.Printf("Warning: Cannot initialize database without logger")
		return c
	}

	dao := NewDao(c.logger, &c.config.Server.Database)
	if dao == nil {
		log.Printf("Warning: Failed to create DAO")
		return c
	}

	if err := dao.RunMigrations(); err != nil {
		log.Printf("Warning: Failed to run database migrations: %v", err)
		return c
	}

	c.SetDB(dao)
	return c
}

func (c *Core) WithAuth() *Core {
	if c.config == nil {
		log.Printf("Warning: Cannot initialize auth service without configuration")
		return c
	}

	if c.logger == nil {
		log.Printf("Warning: Cannot initialize auth service without logger")
		return c
	}

	if c.dao == nil {
		log.Printf("Warning: Cannot initialize auth service without database connection")
		return c
	}

	return c
}

func (c *Core) WithService() *Core {
	if c.logger == nil {
		log.Printf("Warning: Cannot initialize service without logger")
		return c
	}

	if c.dao == nil {
		log.Printf("Warning: Cannot initialize service without database connection")
		return c
	}

	service := NewService(c.logger, &c.config.Server.Security, c.llm, c.dao)
	c.SetService(service)
	return c
}

func (c *Core) WithHandler() *Core {
	if c.logger == nil {
		log.Printf("Warning: Cannot initialize handler without logger")
		return c
	}

	if c.service == nil {
		log.Printf("Warning: Cannot initialize handler without service")
		return c
	}

	handler := NewHandler(c.logger, c.service)
	c.SetHandler(handler)
	return c
}

func (c *Core) WithServer() *Core {
	if c.logger == nil {
		log.Printf("Warning: Cannot initialize server without logger")
		return c
	}

	if c.handler == nil {
		log.Printf("Warning: Cannot initialize server without handler")
		return c
	}

	if c.service == nil {
		log.Printf("Warning: Cannot initialize server without service")
		return c
	}

	server := NewServer(c.logger, &c.config.Server, c.handler)
	c.SetServer(server)
	server.RegisterRoutes(c.handler, c.service)
	return c
}

func (c *Core) Start() error {
	if c.server == nil {
		return ErrServerRequired
	}

	return c.server.Start()
}

func (c *Core) Config() *config.Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.config
}

func (c *Core) SetConfig(cfg *config.Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = cfg
}

func (c *Core) Logger() *logger.Logger {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.logger
}

func (c *Core) SetLogger(log *logger.Logger) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logger = log
}

func (c *Core) LLM() *LLM {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.llm
}

func (c *Core) SetLLM(llm *LLM) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.llm = llm
}

func (c *Core) Dao() *Dao {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.dao
}

func (c *Core) SetDB(dao *Dao) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dao = dao
}

func (c *Core) Service() *Service {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.service
}

func (c *Core) SetService(svc *Service) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.service = svc
}

func (c *Core) Handler() *Handler {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.handler
}

func (c *Core) SetHandler(h *Handler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handler = h
}

func (c *Core) Server() *Server {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.server
}

func (c *Core) SetServer(s *Server) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.server = s
}

func (c *Core) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.dao != nil {
		c.dao.Close()
	}
}
