//go:build !windows
// +build !windows

package scanner

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	pbar "github.com/elulcao/progress-bar/cmd"
)

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
	var tcpOK, tlsOK, httpOK, h2OK, errCount atomic.Int64
	total := int64(len(targets))
	scanDone := make(chan struct{})
	start := time.Now()

	// Progress bar + live stats (elulcao/progress-bar).
	var pb *pbar.PBar
	if s.Progress {
		pb = pbar.NewPBar()
		pb.Total = pbarScale
		pb.DoneStr = "█"
		pb.OngoingStr = "░"

		go func() {
			barTicker := time.NewTicker(150 * time.Millisecond)
			statsTicker := time.NewTicker(3 * time.Second)
			defer barTicker.Stop()
			defer statsTicker.Stop()
			for {
				select {
				case <-barTicker.C:
					n := completed.Load()
					scaled := int(n * pbarScale / total)
					pb.RenderPBar(scaled)
				case <-statsTicker.C:
					n := completed.Load()
					secs := time.Since(start).Seconds()
					rate := float64(n) / secs
					pb.Println(fmt.Sprintf(
						"  \033[36m%d/%d\033[0m scanned | \033[32mTCP:%d TLS:%d HTTP:%d H2:%d\033[0m | \033[31merr:%d\033[0m | %.0f/s",
						n, total,
						tcpOK.Load(), tlsOK.Load(), httpOK.Load(), h2OK.Load(),
						errCount.Load(), rate,
					))
				case <-scanDone:
					pb.RenderPBar(pbarScale)
					return
				}
			}
		}()
	}

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

				res := Probe(ctx, targets[idx], s.Config)
				results[idx] = res
				if s.OnResult != nil {
					s.OnResult(idx, res)
				}
				if res.TCPSuccess {
					tcpOK.Add(1)
				}
				if res.TLSSuccess {
					tlsOK.Add(1)
				}
				if res.HTTPSuccess {
					httpOK.Add(1)
				}
				if res.HTTP2Success {
					h2OK.Add(1)
				}
				if res.Error != "" {
					errCount.Add(1)
				}
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
		select {
		case jobs <- i:
		case <-ctx.Done():
			break
		}
	}
	close(jobs)
	wg.Wait()

	close(scanDone)
	if pb != nil {
		time.Sleep(200 * time.Millisecond)
		pb.CleanUp()
		fmt.Println()
	}

	elapsed := time.Since(start)
	fmt.Printf("\n  Scan complete in %s — %d targets scanned\n", elapsed.Round(time.Millisecond), total)
	fmt.Printf("  TCP: %d  TLS: %d  HTTP: %d  H2: %d  Errors: %d\n\n",
		tcpOK.Load(), tlsOK.Load(), httpOK.Load(), h2OK.Load(), errCount.Load())

	s.Results = results
}
