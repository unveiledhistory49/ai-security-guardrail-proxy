package inbound

import (
	"ai-security-guardrail-proxy/internal/config"
	"ai-security-guardrail-proxy/internal/pipeline"
)

// InboundStages encapsulates the individual filter stages in Layer 2.
type InboundStages struct {
	RateLimiter        *RateLimiter
	DelimiterSanitizer *DelimiterSanitizer
	InjectionMatcher   *InjectionMatcher
	EntropyAnalyzer    *EntropyAnalyzer
	DLPScanner         *DLPScanner
	CanarySynthesizer  *CanarySynthesizer
}

// NewDefaultInboundStages initializes all Layer 2 inbound inspection stages.
func NewDefaultInboundStages(cfg *config.Config) *InboundStages {
	limiter := NewRateLimiter(0, 0)
	if cfg != nil {
		for _, tc := range cfg.Tenants {
			if tc.RPM > 0 || tc.TPM > 0 {
				limiter.SetTenantLimit(tc.TenantID, tc.RPM, tc.TPM)
			}
		}
	}

	return &InboundStages{
		RateLimiter:        limiter,
		DelimiterSanitizer: NewDelimiterSanitizer(),
		InjectionMatcher:   NewInjectionMatcher(),
		EntropyAnalyzer:    NewEntropyAnalyzer(),
		DLPScanner:         NewDLPScanner(),
		CanarySynthesizer:  NewCanarySynthesizer(DefaultCanarySeed),
	}
}

// NewDefaultPipeline builds an ordered PipelineRunner according to Layer 2 architecture:
// RateLimiter -> DelimiterSanitizer -> InjectionMatcher -> DLPScanner -> EntropyAnalyzer -> CanarySynthesizer
func NewDefaultPipeline(cfg *config.Config) *pipeline.PipelineRunner {
	stages := NewDefaultInboundStages(cfg)
	return pipeline.NewPipelineRunner(
		stages.RateLimiter,
		stages.DelimiterSanitizer,
		stages.InjectionMatcher,
		stages.DLPScanner,
		stages.EntropyAnalyzer,
		stages.CanarySynthesizer,
	)
}
