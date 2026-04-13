package scanner

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hedzr/is/term/color"
	"github.com/hedzr/progressbar/v2"
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

	// Progress bar (hedzr/progressbar).
	var mpb progressbar.MultiPB
	if s.Progress {
		color.Hide()
		mpb = progressbar.New()
		mpb.Add(total, "scanning",
			progressbar.WithBarStepper(0),
			progressbar.WithBarWorker(func(bar progressbar.MiniResizeableBar, exitCh <-chan struct{}) bool {
				ticker := time.NewTicker(200 * time.Millisecond)
				defer ticker.Stop()
				var lastN int64
				for {
					select {
					case <-ticker.C:
						n := completed.Load()
						if delta := n - lastN; delta > 0 {
							bar.Step(delta)
							lastN = n
						}
					case <-scanDone:
						n := completed.Load()
						if delta := n - lastN; delta > 0 {
							bar.Step(delta)
						}
						return false
					case <-exitCh:
						return true
					}
				}
			}),
		)
	}

	start := time.Now()

	var wg sync.WaitGroup
	for w := 0; w < s.Threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Per-worker rate limiter.
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

	// Dispatch with optional global rate limit.
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
	if mpb != nil {
		time.Sleep(300 * time.Millisecond)
		mpb.Close()
		color.Show()
		fmt.Println()
	}

	s.Results = results
}
