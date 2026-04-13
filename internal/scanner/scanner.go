package scanner

import (
	"context"
	"sync"
)

// Scanner coordinates the concurrent probing of targets.
type Scanner struct {
	Threads int
	Config  *ProbeConfig

	// Results are collected here after Run completes.
	Results []ProbeResult
}

// Run dispatches all targets across a bounded worker pool. It blocks until
// every target has been probed or ctx is cancelled.
func (s *Scanner) Run(ctx context.Context, targets []Target) {
	results := make([]ProbeResult, len(targets))
	jobs := make(chan int, s.Threads)

	var wg sync.WaitGroup
	for w := 0; w < s.Threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				results[idx] = Probe(ctx, targets[idx], s.Config)
			}
		}()
	}

	for i := range targets {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	s.Results = results
}
