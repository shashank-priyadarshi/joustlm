package logger

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"go.ssnk.in/joustlm/config"
)

type Logger struct {
	log *slog.Logger

	config *config.Logging
	caller config.Caller
	level  Level
	format Format
}

func New(opts ...func(*Logger)) Logger {
	l := &Logger{
		log: nil,
		config: &config.Logging{
			CallerDepth: map[config.Caller]int{
				config.Backend:  8,
				config.Frontend: 8,
			},
		},
		caller: config.Backend,
		level:  Info,
		format: Json,
	}

	for _, opt := range opts {
		opt(l)
	}

	initialize(l)

	return *l
}

func initialize(logger *Logger) {
	opts := &slog.HandlerOptions{}
	var handler slog.Handler

	opts.AddSource = logger.level == Debug
	opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
		dbgLvlSource := func() {
			_, file, line, ok := runtime.Caller(logger.config.CallerDepth[logger.caller])
			if ok {
				relFile := file
				if !strings.Contains(file, "logger.go") && !strings.Contains(file, "runtime") && !strings.Contains(file, "log/slog") {
					if rel, err := filepath.Rel(".", file); err == nil {
						relFile = rel
					} else {
						if idx := strings.Index(file, "/joustlm/"); idx != -1 {
							relFile = file[idx+1:]
						}
					}

					a.Value = slog.StringValue(relFile + ":" + strconv.Itoa(line))
				} else if strings.Contains(file, "/mod/") && strings.Contains(file, "logger.go") {
					relFile = file
					_, file, line, ok = runtime.Caller(logger.config.CallerDepth[logger.caller] + 1)
					if ok {
						if idx := strings.Index(file, "/mod/"); idx != -1 {
							relFile = file[idx:]
						}
					}
					a.Value = slog.StringValue(relFile + ":" + strconv.Itoa(line))
				}
			}
		}

		switch a.Key {
		case slog.LevelKey:
			level, ok := a.Value.Any().(slog.Level)
			if !ok {
				level = slog.LevelInfo
			}

			levelLabel := ""
			switch level {
			case slog.LevelError:
				levelLabel = "ERR"
			case slog.LevelDebug:
				levelLabel = "DBG"
			case slog.LevelWarn:
				levelLabel = "WRN"
			default:
				levelLabel = "INF"
			}

			a.Value = slog.StringValue(levelLabel)
		case slog.SourceKey:
			dbgLvlSource()
		}

		return a
	}

	switch logger.level {
	case "error":
		opts.Level = slog.LevelError
	case "fatal":
		opts.Level = Fatal
	case "debug":
		opts.Level = slog.LevelDebug
	case "warn":
		opts.Level = slog.LevelWarn
	default:
		opts.Level = slog.LevelInfo
	}

	switch logger.format {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	default:
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	logger.log = slog.New(handler)
}

func SetConfig(config *config.Logging) func(*Logger) {
	return func(logger *Logger) {
		logger.config = config
	}
}

func SetCaller(caller config.Caller) func(*Logger) {
	return func(logger *Logger) {
		logger.caller = caller
	}
}

type Level string

const (
	Fatal = slog.Level(12)
	Panic = slog.Level(16)

	Error Level = "error"
	Warn  Level = "warn"
	Info  Level = "info"
	Debug Level = "debug"
)

var LevelNames = map[slog.Leveler]string{
	Fatal: "FTL",
	Panic: "PAN",
}

func (l Level) String() string {
	return string(l)
}

func SetLevel(level Level) func(*Logger) {
	return func(logger *Logger) {
		if len(level) != 0 {
			logger.level = level
		}
	}
}

type Format string

const (
	Json  Format = "json"
	Text  Format = "text"
	Proto Format = "proto"
)

func (f Format) String() string {
	return string(f)
}

func SetFormat(format Format) func(*Logger) {
	return func(logger *Logger) {
		if len(format) != 0 {
			logger.format = format
		}
	}
}

func (l Logger) Debug(msg string, args ...any) {
	l.log.Debug(msg, args...)
}

func (l Logger) Info(msg string, args ...any) {
	l.log.Info(msg, args...)
}

func (l Logger) Warn(msg string, args ...any) {
	l.log.Warn(msg, args...)
}

func (l Logger) Error(err string, args ...any) {
	l.log.Error(err, args...)
}

func (l Logger) Fatal(err string, args ...any) {
	l.Error(err, args...)
	os.Exit(1)
}

func (l Logger) Panic(err error, args ...any) {
	panic(err)
}
