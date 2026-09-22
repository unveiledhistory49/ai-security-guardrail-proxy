package resilience

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCircuitBreaker_InitialStateClosed(t *testing.T) {
	cb := NewCircuitBreaker(Config{
		FailureThreshold: 3,
		CooldownDuration: 100 * time.Millisecond,
		HalfOpenProbes:   2,
	})

	if cb.State() != StateClosed {
		t.Fatalf("expected initial state CLOSED, got %v", cb.State())
	}

	for i := 0; i < 10; i++ {
		if err := cb.Allow(); err != nil {
			t.Fatalf("expected Allow() to succeed in CLOSED state, got: %v", err)
		}
		cb.RecordSuccess()
	}

	if cb.State() != StateClosed {
		t.Fatalf("expected state to remain CLOSED")
	}
}

func TestCircuitBreaker_TripToOpenAndFailFast(t *testing.T) {
	cb := NewCircuitBreaker(Config{
		FailureThreshold: 3,
		CooldownDuration: 150 * time.Millisecond,
		HalfOpenProbes:   2,
	})

	// 1st failure
	cb.RecordFailure()
	if cb.State() != StateClosed {
		t.Fatalf("state should be CLOSED after 1 failure")
	}

	// 2nd failure
	cb.RecordFailure()
	if cb.State() != StateClosed {
		t.Fatalf("state should be CLOSED after 2 failures")
	}

	// 3rd failure trips the breaker to OPEN
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Fatalf("expected state to be OPEN after 3 failures, got %v", cb.State())
	}

	// Must fail-fast immediately without waiting
	err := cb.Allow()
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen, got %v", err)
	}
}

func TestCircuitBreaker_Transitions_Closed_Open_HalfOpen_Closed(t *testing.T) {
	var transitions []string
	cb := NewCircuitBreaker(Config{
		FailureThreshold: 2,
		CooldownDuration: 50 * time.Millisecond,
		HalfOpenProbes:   2,
	})
	cb.SetOnStateChange(func(from, to State) {
		transitions = append(transitions, from.String()+"->"+to.String())
	})

	// 1. Trip to OPEN
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Fatalf("expected OPEN state, got %v", cb.State())
	}

	// Fail fast in OPEN
	if err := cb.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen in OPEN state")
	}

	// 2. Wait for cooldown to expire -> HALF-OPEN
	time.Sleep(60 * time.Millisecond)

	// In Half-Open, probe 1 allowed
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected probe 1 to be allowed in HALF-OPEN, got %v", err)
	}
	cb.RecordSuccess()

	// Probe 2 allowed
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected probe 2 to be allowed in HALF-OPEN, got %v", err)
	}
	cb.RecordSuccess()

	// 3. Should now have transitioned back to CLOSED
	if cb.State() != StateClosed {
		t.Fatalf("expected state to be CLOSED after 2 successful probes, got %v", cb.State())
	}

	expectedTransitions := []string{"CLOSED->OPEN", "OPEN->HALF-OPEN", "HALF-OPEN->CLOSED"}
	if len(transitions) != len(expectedTransitions) {
		t.Fatalf("expected transitions %v, got %v", expectedTransitions, transitions)
	}
	for i, tr := range expectedTransitions {
		if transitions[i] != tr {
			t.Errorf("transition %d: expected %s, got %s", i, tr, transitions[i])
		}
	}
}

func TestCircuitBreaker_HalfOpen_ProbeFailure_TripsBackToOpen(t *testing.T) {
	cb := NewCircuitBreaker(Config{
		FailureThreshold: 2,
		CooldownDuration: 50 * time.Millisecond,
		HalfOpenProbes:   2,
	})

	// Trip to OPEN
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Fatalf("expected OPEN")
	}

	// Wait cooldown
	time.Sleep(60 * time.Millisecond)

	// Allow probe in Half-Open
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected probe allowed")
	}

	// Probe fails -> should immediately trip back to OPEN
	cb.RecordFailure()
	if cb.State() != StateOpen {
		t.Fatalf("expected state to trip back to OPEN on probe failure, got %v", cb.State())
	}

	// Next Allow() must be rejected
	if err := cb.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen after probe failure")
	}
}

func TestCircuitBreaker_ManualTripAndReset(t *testing.T) {
	cb := NewCircuitBreaker(Config{
		FailureThreshold: 5,
		CooldownDuration: 10 * time.Second,
		HalfOpenProbes:   2,
	})

	cb.Trip()
	if cb.State() != StateOpen {
		t.Fatalf("expected OPEN after Trip()")
	}

	cb.Reset()
	if cb.State() != StateClosed {
		t.Fatalf("expected CLOSED after Reset()")
	}
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected Allow() to succeed after Reset()")
	}
}

func TestCircuitBreaker_ConcurrentSafety(t *testing.T) {
	cb := NewCircuitBreaker(Config{
		FailureThreshold: 10,
		CooldownDuration: 20 * time.Millisecond,
		HalfOpenProbes:   2,
	})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = cb.Allow()
				if j%3 == 0 {
					cb.RecordFailure()
				} else {
					cb.RecordSuccess()
				}
				_ = cb.State()
			}
		}(i)
	}

	wg.Wait()
}
