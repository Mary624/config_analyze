package domain

import (
	"fmt"
	"regexp"
)

type Vulnerability struct {
	Field      Field
	WrongValue any
}

var regHash = regexp.MustCompile(`^[A-Z0-9]{32}$`)

type Level int

func (l Level) String() string {
	switch l {
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

const (
	Low Level = iota
	Medium
	High
)

type VulnerabilityCheck struct {
	DebugEnabled bool
	LogLevel     string
	Password     string
	Host         string
	Safety       bool
	Algorithm    string
}

type Field interface {
	Info(value any) string
	Level() Level
	IsNormalValue(value any) bool
}

type DebugMode struct {
}

func (d DebugMode) Info(value any) string {
	return "логирование в debug-режиме. Поменяйте режим на более избирательный (info+)."
}

func (d DebugMode) Level() Level {
	return Low
}

func (d DebugMode) IsNormalValue(value any) bool {
	if _, ok := value.(bool); !ok {
		return false
	}
	return !value.(bool)
}

type LogLevel struct {
}

func (d LogLevel) Info(value any) string {
	return "логирование в debug-режиме. Поменяйте режим на более избирательный (info+)."
}

func (d LogLevel) Level() Level {
	return Low
}

func (d LogLevel) IsNormalValue(value any) bool {
	if _, ok := value.(string); ok {
		return value.(string) != "debug"
	}
	if _, ok := value.(map[string]any); !ok {
		return false
	}
	return value.(map[string]any)["level"] != "debug"
}

type Password struct {
}

func (p Password) Info(value any) string {
	return "пароль хранится в открытом виде. Поменяйте его на хеш."
}

func (d Password) Level() Level {
	return High
}

func (p Password) IsNormalValue(value any) bool {
	if _, ok := value.(string); !ok {
		return false
	}
	return regHash.MatchString(value.(string))
}

type Host struct {
}

func (h Host) Info(value any) string {
	if _, ok := value.(string); !ok {
		return ""
	}
	return fmt.Sprintf("используется '%s' без ограничений. Поменяйте его на другое значение.", value.(string))
}

// TODO
func (d Host) Level() Level {
	return High
}

func (h Host) IsNormalValue(value any) bool {
	if _, ok := value.(string); !ok {
		return false
	}
	return value.(string) != "0.0.0.0"
}

type Safety struct {
}

func (s Safety) Info(value any) string {
	if _, ok := value.(bool); !ok {
		return ""
	}
	return "используется небезопасный протокол. Поменяйте его на безопасный."
}

func (d Safety) Level() Level {
	return High
}

func (s Safety) IsNormalValue(value any) bool {
	if _, ok := value.(bool); !ok {
		return false
	}
	return value.(bool)
}

type Algorithm struct {
	Value string
}

var unsafeAlgorithms = map[string]struct{}{
	"MD5":  {},
	"SHA1": {},
	"DES":  {},
}

func (a Algorithm) Info(value any) string {
	if _, ok := value.(string); !ok {
		return ""
	}
	return fmt.Sprintf("используется небезопасный алгоритм '%s'. Поменяйте его на безопасный.", value.(string))
}

func (d Algorithm) Level() Level {
	return High
}

func (a Algorithm) IsNormalValue(value any) bool {
	if _, ok := value.(string); !ok {
		return false
	}
	if _, ok := unsafeAlgorithms[value.(string)]; ok {
		return false
	}
	return true
}
