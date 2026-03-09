package core

import "context"

type Scanner interface {
	Name() string
	Type() ScanType
	Init(cfg *Config) error
	Scan(ctx context.Context, paths []string, findings chan<- Finding) error
	Close() error
}
