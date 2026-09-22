package outbound

import (
	"testing"
)

func TestSchemaValidator_ValidChatCompletion(t *testing.T) {
	validator := NewSchemaValidator()

	validJSON := []byte(`{
		"id": "chatcmpl-123",
		"object": "chat.completion",
		"created": 1677652288,
		"model": "gpt-4",
		"choices": [{
			"index": 0,
			"message": {
				"role": "assistant",
				"content": "Hello! How can I help you today?"
			},
			"finish_reason": "stop"
		}],
		"usage": {
			"prompt_tokens": 9,
			"completion_tokens": 12,
			"total_tokens": 21
		}
	}`)

	if err := validator.Validate(validJSON); err != nil {
		t.Fatalf("expected valid JSON completion to pass, got error: %v", err)
	}
}

func TestSchemaValidator_ValidToolCall(t *testing.T) {
	validator := NewSchemaValidator()

	validToolCall := []byte(`{
		"id": "chatcmpl-456",
		"choices": [{
			"index": 0,
			"message": {
				"role": "assistant",
				"tool_calls": [{
					"id": "call_abc123",
					"type": "function",
					"function": {
						"name": "lookup_weather",
						"arguments": "{\"location\":\"San Francisco, CA\",\"unit\":\"celsius\"}"
					}
				}]
			}
		}]
	}`)

	if err := validator.Validate(validToolCall); err != nil {
		t.Fatalf("expected valid tool call response to pass, got error: %v", err)
	}
}

func TestSchemaValidator_InvalidJSON(t *testing.T) {
	validator := NewSchemaValidator()

	invalidPayloads := [][]byte{
		[]byte(``),
		[]byte(`{"id": "chatcmpl-1", choices: `),
		[]byte(`<html><body>502 Bad Gateway</body></html>`),
		[]byte(`{truncated: true`),
	}

	for _, payload := range invalidPayloads {
		if err := validator.Validate(payload); err == nil {
			t.Fatalf("expected error for invalid JSON %q, got nil", string(payload))
		}
	}
}

func TestSchemaValidator_InvalidToolCallArguments(t *testing.T) {
	validator := NewSchemaValidator()

	invalidToolArgs := []byte(`{
		"id": "chatcmpl-789",
		"choices": [{
			"index": 0,
			"message": {
				"role": "assistant",
				"tool_calls": [{
					"id": "call_xyz",
					"type": "function",
					"function": {
						"name": "dangerous_query",
						"arguments": "{unquoted_key: broken_value"
					}
				}]
			}
		}]
	}`)

	if err := validator.Validate(invalidToolArgs); err == nil {
		t.Fatalf("expected error for malformed tool call JSON arguments, got nil")
	}
}

func TestSchemaValidator_MissingChoices(t *testing.T) {
	validator := NewSchemaValidator()

	emptyChoices := []byte(`{
		"id": "chatcmpl-000",
		"choices": []
	}`)

	if err := validator.Validate(emptyChoices); err == nil {
		t.Fatalf("expected error for empty choices array, got nil")
	}
}

func TestSchemaValidator_UpstreamErrorObject(t *testing.T) {
	validator := NewSchemaValidator()

	upstreamErr := []byte(`{
		"error": {
			"message": "Model overloaded, please retry later.",
			"type": "server_error",
			"code": "model_overloaded"
		}
	}`)

	if err := validator.Validate(upstreamErr); err != nil {
		t.Fatalf("expected valid upstream error response to pass schema, got error: %v", err)
	}
}
