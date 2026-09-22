package inbound

import (
	"strings"

	"ai-security-guardrail-proxy/internal/pipeline"
)

// DefaultInjectionSignatures contains a curated dictionary of known prompt injection phrases.
var DefaultInjectionSignatures = []string{
	"ignore previous instructions",
	"ignore all previous instructions",
	"ignore all instructions",
	"ignore above instructions",
	"ignore all previous directions",
	"system override",
	"jailbreak",
	"jailbroken",
	"you are now an unrestricted",
	"dan mode",
	"disregard all previous rules",
	"disregard previous instructions",
	"developer mode enabled",
	"bypass all restrictions",
	"pretend you are an unrestricted",
	"act as an unrestricted",
	"do anything now",
}

type acNode struct {
	next   [256]uint32
	fail   uint32
	output []string
}

// AhoCorasick implements a high-throughput deterministic finite automaton (DFA)
// multi-pattern matcher executing in guaranteed linear O(N + M) single-pass time.
type AhoCorasick struct {
	nodes []acNode
}

// NewAhoCorasick compiles a set of pattern strings into an optimized DFA.
func NewAhoCorasick(patterns []string) *AhoCorasick {
	ac := &AhoCorasick{
		nodes: make([]acNode, 1, 1024), // root state 0
	}

	// 1. Build trie with lowercase ASCII keys
	for _, pattern := range patterns {
		clean := strings.ToLower(strings.TrimSpace(pattern))
		if clean == "" {
			continue
		}
		curr := uint32(0)
		for i := 0; i < len(clean); i++ {
			b := clean[i]
			next := ac.nodes[curr].next[b]
			if next == 0 {
				next = uint32(len(ac.nodes))
				ac.nodes = append(ac.nodes, acNode{})
				ac.nodes[curr].next[b] = next
			}
			curr = next
		}
		ac.nodes[curr].output = append(ac.nodes[curr].output, pattern)
	}

	// 2. BFS to build failure links and convert trie to complete DFA
	queue := make([]uint32, 0, len(ac.nodes))

	// Depth 1 states fail to root (0)
	for b := 0; b < 256; b++ {
		child := ac.nodes[0].next[b]
		if child != 0 {
			ac.nodes[child].fail = 0
			queue = append(queue, child)
		}
	}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		failState := ac.nodes[curr].fail

		for b := 0; b < 256; b++ {
			child := ac.nodes[curr].next[b]
			if child != 0 {
				// Failure state of child is failState's transition on byte b
				ac.nodes[child].fail = ac.nodes[failState].next[b]
				// Inherit matching outputs from failure state
				if len(ac.nodes[ac.nodes[child].fail].output) > 0 {
					ac.nodes[child].output = append(ac.nodes[child].output, ac.nodes[ac.nodes[child].fail].output...)
				}
				queue = append(queue, child)
			} else {
				// Convert to complete DFA: transition leads directly to failState's transition
				ac.nodes[curr].next[b] = ac.nodes[failState].next[b]
			}
		}
	}

	return ac
}

// Search scans text in a single O(N) pass, returning the first matched pattern if found.
func (ac *AhoCorasick) Search(text []byte) (string, bool) {
	curr := uint32(0)
	for i := 0; i < len(text); i++ {
		b := text[i]
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		curr = ac.nodes[curr].next[b]
		if len(ac.nodes[curr].output) > 0 {
			return ac.nodes[curr].output[0], true
		}
	}
	return "", false
}

// InjectionMatcher is a pipeline.Stage that scans payloads for prompt injection attacks
// using the Aho-Corasick automaton.
type InjectionMatcher struct {
	automaton *AhoCorasick
}

// NewInjectionMatcher constructs an InjectionMatcher with default curated injection signatures.
func NewInjectionMatcher(customPatterns ...[]string) *InjectionMatcher {
	patterns := DefaultInjectionSignatures
	if len(customPatterns) > 0 && len(customPatterns[0]) > 0 {
		patterns = customPatterns[0]
	}
	return &InjectionMatcher{
		automaton: NewAhoCorasick(patterns),
	}
}

// Name returns the stage name.
func (m *InjectionMatcher) Name() string {
	return "injection_matcher"
}

// FailClosed returns true to ensure fail-closed security.
func (m *InjectionMatcher) FailClosed() bool {
	return true
}

// Execute performs single-pass multi-pattern matching on CleanPayload.
func (m *InjectionMatcher) Execute(ctx *pipeline.PipelineContext) pipeline.StageResult {
	if len(ctx.CleanPayload) == 0 {
		return pipeline.StageContinue
	}

	if match, found := m.automaton.Search(ctx.CleanPayload); found {
		ctx.MatchedRuleID = "PROMPT_INJECTION_DETECTED"
		ctx.ViolationType = "INJECTION: " + match
		return pipeline.StageTripwire
	}

	return pipeline.StageContinue
}
