package processor

import "config_analyze/internal/domain"

type Processor interface {
	Process(data []byte) ([]domain.Vulnerability, error)
}
