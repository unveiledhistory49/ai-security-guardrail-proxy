package resilience

import (
	"errors"
	"sync"
	"time"
)

// State represents the three states of the upstream circuit breaker state machine.
type State int

const (
	StateClosed State = iota
	StateHalfOpen
	StateOpen
)

// String returns the canonical human-readable state label.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateHalfOpen:
		return "HALF-OPEN"
	case StateOpen:
		return "OPEN"
	default:
		return "UNKNOWN"
	}
}

// ErrCircuitOpen is returned immediately when the circuit is in OPEN state,
// failing fast without executing any network calls.
var ErrCircuitOpen = errors.New("circuit breaker is OPEN")

// Config controls failure thresholds, cooldowns, and probe counts.
type Config struct {
	// FailureThreshold is the number of consecutive upstream failures to trip the circuit to OPEN.
	FailureThreshold uint32
	// CooldownDuration is the duration the circuit remains OPEN before transitioning to HALF-OPEN.
	CooldownDuration time.Duration
	// HalfOpenProbes is the number of successful consecutive probes required in HALF-OPEN to reset to CLOSED.
	HalfOpenProbes uint32
}

// DefaultConfig provides standard production defaults.
func DefaultConfig() Config {
	return Config{
		FailureThreshold: 5,
		CooldownDuration: 30 * time.Second,
		HalfOpenProbes:   2,
	}
}

// CircuitBreaker implements a thread-safe three-state machine protecting downstream systems
// and isolating upstream model failure cascades.
type CircuitBreaker struct {
	mu                   sync.Mutex
	config               Config
	state                State
	consecutiveFailures  uint32
	consecutiveSuccesses uint32
	lastTripTime         time.Time
	probesInFlight       uint32
	onStateChange        func(from, to State)
}

// NewCircuitBreaker constructs an initialized CircuitBreaker with the given configuration.
func NewCircuitBreaker(cfg Config) *CircuitBreaker {
	if cfg.FailureThreshold == 0 {
		cfg.FailureThreshold = 5
	}
	if cfg.CooldownDuration <= 0 {
		cfg.CooldownDuration = 30 * time.Second
	}
	if cfg.HalfOpenProbes == 0 {
		cfg.HalfOpenProbes = 2
	}

	return &CircuitBreaker{
		config: cfg,
		state:  StateClosed,
	}
}

// SetOnStateChange registers a callback triggered on any state transition.
func (cb *CircuitBreaker) SetOnStateChange(fn func(from, to State)) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.onStateChange = fn
}

// Allow checks whether an upstream request is permitted under the current state.
// In CLOSED: returns nil.
// In OPEN: checks if cooldown has expired; if so, transitions to HALF-OPEN and permits probe. Otherwise returns ErrCircuitOpen.
// In HALF-OPEN: permits up to HalfOpenProbes requests.
func (cb *CircuitBreaker) Allow() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	switch cb.state {
	case StateClosed:
		return nil

	case StateOpen:
		if now.Sub(cb.lastTripTime) >= cb.config.CooldownDuration {
			// Cooldown elapsed: transition to HALF-OPEN
			oldState := cb.state
			cb.state = StateHalfOpen
			cb.consecutiveSuccesses = 0
			cb.probesInFlight = 1
			if cb.onStateChange != nil {
				cb.onStateChange(oldState, cb.state)
			}
			return nil
		}
		return ErrCircuitOpen

	case StateHalfOpen:
		if cb.probesInFlight >= cb.config.HalfOpenProbes {
			return ErrCircuitOpen
		}
		cb.probesInFlight++
		return nil

	default:
		return nil
	}
}

// RecordSuccess records a successful upstream interaction.
// In CLOSED: resets consecutive failures.
// In HALF-OPEN: increments successful probes; transitions to CLOSED if threshold reached.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		cb.consecutiveFailures = 0

	case StateHalfOpen:
		if cb.probesInFlight > 0 {
			cb.probesInFlight--
		}
		cb.consecutiveSuccesses++
		if cb.consecutiveSuccesses >= cb.config.HalfOpenProbes {
			oldState := cb.state
			cb.state = StateClosed
			cb.consecutiveFailures = 0
			cb.consecutiveSuccesses = 0
			cb.probesInFlight = 0
			if cb.onStateChange != nil {
				cb.onStateChange(oldState, cb.state)
			}
		}

	case StateOpen:
		cb.probesInFlight = 0
	}
}

// RecordFailure records an upstream failure (network error, timeout, or 5xx response).
// In CLOSED: increments consecutive failures; transitions to OPEN if threshold reached.
// In HALF-OPEN: any failure immediately trips back to OPEN.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		cb.consecutiveFailures++
		if cb.consecutiveFailures >= cb.config.FailureThreshold {
			oldState := cb.state
			cb.state = StateOpen
			cb.lastTripTime = time.Now()
			cb.probesInFlight = 0
			cb.consecutiveSuccesses = 0
			if cb.onStateChange != nil {
				cb.onStateChange(oldState, cb.state)
			}
		}

	case StateHalfOpen:
		oldState := cb.state
		cb.state = StateOpen
		cb.lastTripTime = time.Now()
		cb.probesInFlight = 0
		cb.consecutiveSuccesses = 0
		cb.consecutiveFailures = cb.config.FailureThreshold
		if cb.onStateChange != nil {
			cb.onStateChange(oldState, cb.state)
		}

	case StateOpen:
		cb.lastTripTime = time.Now()
	}
}

// State returns the current State, accounting for automatic cooldown expiration.
func (cb *CircuitBreaker) State() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == StateOpen && time.Since(cb.lastTripTime) >= cb.config.CooldownDuration {
		return StateHalfOpen
	}
	return cb.state
}

// Trip forces the circuit breaker into OPEN state immediately.
func (cb *CircuitBreaker) Trip() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state != StateOpen {
		oldState := cb.state
		cb.state = StateOpen
		cb.lastTripTime = time.Now()
		cb.consecutiveFailures = cb.config.FailureThreshold
		cb.probesInFlight = 0
		cb.consecutiveSuccesses = 0
		if cb.onStateChange != nil {
			cb.onStateChange(oldState, cb.state)
		}
	}
}

// Reset resets the circuit breaker to CLOSED state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state != StateClosed {
		oldState := cb.state
		cb.state = StateClosed
		cb.consecutiveFailures = 0
		cb.consecutiveSuccesses = 0
		cb.probesInFlight = 0
		if cb.onStateChange != nil {
			cb.onStateChange(oldState, cb.state)
		}
	}
}

// ConsecutiveFailures returns the current consecutive failure count.
func (cb *CircuitBreaker) ConsecutiveFailures() uint32 {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.consecutiveFailures
}
