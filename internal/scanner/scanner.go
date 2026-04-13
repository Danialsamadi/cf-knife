package scanner

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	pbar "github.com/elulcao/progress-bar/cmd"
)

// Scanner coordinates the concurrent probing of targets.
type Scanner struct {
	Threads   int
	Config    *ProbeConfig
	Rate      int // global ops/sec; 0 = unlimited
	RateLimit int // per-worker ops/sec; 0 = unlimited
	Progress  bool
	Verbose   bool

	Results []ProbeResult
}

const pbarScale = 10000

// Run dispatches all targets across a bounded worker pool with optional
// global and per-worker rate limiting. It blocks until every target has
// been probed or ctx is cancelled.
func (s *Scanner) Run(ctx context.Context, targets []Target) {
	results := make([]ProbeResult, len(targets))
	jobs := make(chan int, s.Threads)

	// Global rate limiter: a ticker that gates dispatch.
	var globalTick <-chan time.Time
	var globalTicker *time.Ticker
	if s.Rate > 0 {
		globalTicker = time.NewTicker(time.Second / time.Duration(s.Rate))
		globalTick = globalTicker.C
		defer globalTicker.Stop()
	}

	var completed atomic.Int64
	total := int64(len(targets))
	scanDone := make(chan struct{})

	// Progress bar (elulcao/progress-bar).
	var pb *pbar.PBar
	if s.Progress {
		pb = pbar.NewPBar()
		pb.Total = pbarScale
		pb.DoneStr = "█"
		pb.OngoingStr = "░"
		pb.SignalHandler()

		go func() {
			ticker := time.NewTicker(150 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					n := completed.Load()
					scaled := int(n * pbarScale / total)
					pb.RenderPBar(scaled)
				case <-scanDone:
					pb.RenderPBar(pbarScale)
					return
				}
			}
		}()
	}

	start := time.Now()

	var wg sync.WaitGroup
	for w := 0; w < s.Threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var workerTick <-chan time.Time
			var workerTicker *time.Ticker
			if s.RateLimit > 0 {
				workerTicker = time.NewTicker(time.Second / time.Duration(s.RateLimit))
				workerTick = workerTicker.C
				defer workerTicker.Stop()
			}

			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				if workerTick != nil {
					select {
					case <-workerTick:
					case <-ctx.Done():
						return
					}
				}

				results[idx] = Probe(ctx, targets[idx], s.Config)
				n := completed.Add(1)
				if s.Verbose && n%500 == 0 {
					elapsed := time.Since(start).Seconds()
					fmt.Printf("  [%d/%d] %.0f targets/sec\n", n, len(targets), float64(n)/elapsed)
				}
			}
		}()
	}

	for i := range targets {
		if ctx.Err() != nil {
			break
		}
		if globalTick != nil {
			select {
			case <-globalTick:
			case <-ctx.Done():
				break
			}
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	close(scanDone)
	if pb != nil {
		time.Sleep(200 * time.Millisecond)
		pb.CleanUp()
		fmt.Println()
	}

	s.Results = results
}
