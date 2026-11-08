package telegraph

import (
	"fmt"
	"sync"
	"time"
)

// DailyBudget caps network spend per UTC day and bounds concurrent paid calls.
// Reservations count against the cap until committed or released, so parallel
// purchases cannot jointly exceed it.
type DailyBudget struct {
	mu            sync.Mutex
	CapMinor      int64
	MaxConcurrent int
	day           string
	spent         int64
	reserved      int64
	inflight      int
	now           func() time.Time
}

func NewDailyBudget(capMinor int64, maxConcurrent int, alreadySpentToday int64) *DailyBudget {
	b := &DailyBudget{CapMinor: capMinor, MaxConcurrent: maxConcurrent, now: time.Now}
	b.day = b.today()
	b.spent = alreadySpentToday
	return b
}

func (b *DailyBudget) today() string { return b.now().UTC().Format("2006-01-02") }

func (b *DailyBudget) rollover() {
	if d := b.today(); d != b.day {
		b.day, b.spent = d, 0
	}
}

func (b *DailyBudget) Reserve(amount int64) (func(spent bool), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rollover()
	if b.MaxConcurrent > 0 && b.inflight >= b.MaxConcurrent {
		return nil, fmt.Errorf("concurrent paid request limit %d reached", b.MaxConcurrent)
	}
	if b.spent+b.reserved+amount > b.CapMinor {
		return nil, fmt.Errorf("daily spend cap %d reached (spent %d)", b.CapMinor, b.spent)
	}
	b.reserved += amount
	b.inflight++
	var once sync.Once
	return func(spent bool) {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.reserved -= amount
			b.inflight--
			if spent {
				b.spent += amount
			}
		})
	}, nil
}

// Snapshot returns (spent today, cap).
func (b *DailyBudget) Snapshot() (int64, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rollover()
	return b.spent, b.CapMinor
}
