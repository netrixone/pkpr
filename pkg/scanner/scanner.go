package scanner

import (
	"context"

	"github.com/netrixone/naabu-probe/pkg/result"
	"github.com/netrixone/naabu-probe/pkg/runner"
	"github.com/projectdiscovery/clistats"
)

type Scanner struct {
	Results  []*result.HostResult
	OnResult result.ResultCallback
	runner   *runner.Runner
}

func NewScanner(options *Options) (*Scanner, error) {
	// Init the scan runner.
	scanRunner, err := runner.NewRunner(options.RunnerOptions)
	if err != nil {
		return nil, err
	}

	scanner := &Scanner{
		Results: make([]*result.HostResult, 0),
		runner:  scanRunner,
	}

	// Collect the results on the fly.
	options.RunnerOptions.OnResult = func(res *result.HostResult) {
		scanner.Results = append(scanner.Results, res)
		if scanner.OnResult != nil {
			scanner.OnResult(res)
		}
	}

	return scanner, nil
}

func (s *Scanner) Run(ctx context.Context) error {
	return s.runner.RunEnumeration(ctx)
}

func (s *Scanner) Stats() clistats.StatisticsClient {
	return s.runner.Stats()
}

func (s *Scanner) Close() {
	s.runner.Close()
}
