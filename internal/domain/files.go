package domain

import (
	"encoding/json"

	"github.com/goccy/go-yaml"
)

type Format interface {
	GetUnmarshaler() func(data []byte, v any) error
}

type JSON struct {
}

func (j JSON) GetUnmarshaler() func(data []byte, v any) error {
	return json.Unmarshal
}

type YAML struct {
}

func (j YAML) GetUnmarshaler() func(data []byte, v any) error {
	return yaml.Unmarshal
}
