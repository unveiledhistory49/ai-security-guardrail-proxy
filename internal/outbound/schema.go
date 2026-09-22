package outbound

import (
	"encoding/json"
	"fmt"
)

const (
	// RuleSchemaValidationFailed identifies an invalid or corrupted outbound JSON response.
	RuleSchemaValidationFailed = "SCHEMA_VALIDATION_FAILED"
)

// SchemaValidator verifies JSON syntax and structured output schema compliance.
type SchemaValidator struct{}

// NewSchemaValidator constructs a new SchemaValidator.
func NewSchemaValidator() *SchemaValidator {
	return &SchemaValidator{}
}

// chatCompletionChoice mirrors the minimal choice structure in OpenAI chat completion format.
type chatCompletionChoice struct {
	Index   int `json:"index"`
	Message *struct {
		Role      string `json:"role"`
		Content   any    `json:"content"`
		ToolCalls []struct {
			ID       string `json:"id"`
			Type     string `json:"type"`
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
	} `json:"message"`
}

type chatCompletionResponse struct {
	ID      *string                `json:"id"`
	Choices []chatCompletionChoice `json:"choices"`
	Error   *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    any    `json:"code"`
	} `json:"error"`
}

// Validate checks whether the payload is valid JSON and complies with expected completion schema.
// Returns an error if JSON is malformed or structured tool calls contain invalid arguments.
func (s *SchemaValidator) Validate(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty response body")
	}

	// 1. Fundamental JSON syntax check
	if !json.Valid(data) {
		return fmt.Errorf("invalid JSON syntax: %s", string(data))
	}

	// 2. Decode top-level structure
	var resp chatCompletionResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	// If the upstream returned a standard API error object, that is a valid JSON error response
	if resp.Error != nil {
		if resp.Error.Message == "" {
			return fmt.Errorf("upstream error object missing message")
		}
		return nil
	}

	// If choices array is present, validate structure of choices and tool calls
	if resp.Choices != nil {
		if len(resp.Choices) == 0 {
			return fmt.Errorf("choices array must not be empty")
		}

		for i, choice := range resp.Choices {
			if choice.Message == nil {
				return fmt.Errorf("choice %d missing message object", i)
			}

			// Validate tool calls if present
			for tIdx, tc := range choice.Message.ToolCalls {
				if tc.ID == "" {
					return fmt.Errorf("choice %d tool call %d missing id", i, tIdx)
				}
				if tc.Type == "" {
					return fmt.Errorf("choice %d tool call %d missing type", i, tIdx)
				}
				if tc.Function.Name == "" {
					return fmt.Errorf("choice %d tool call %d missing function name", i, tIdx)
				}
				if tc.Function.Arguments == "" {
					return fmt.Errorf("choice %d tool call %d empty function arguments", i, tIdx)
				}
				if !json.Valid([]byte(tc.Function.Arguments)) {
					return fmt.Errorf("choice %d tool call %d arguments is not valid JSON: %s", i, tIdx, tc.Function.Arguments)
				}
			}
		}
	}

	return nil
}
