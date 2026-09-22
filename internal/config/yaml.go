package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// YAMLToJSON converts a YAML document into JSON bytes using a self-contained,
// standard-library-only parser. Supports key-value maps, nested indented maps,
// lists (- item or - key: value), scalars (strings, ints, floats, booleans),
// and comments.
func YAMLToJSON(yamlData []byte) ([]byte, error) {
	node, err := parseYAML(yamlData)
	if err != nil {
		return nil, err
	}
	return json.Marshal(node)
}

type yamlLine struct {
	indent  int
	content string
	lineNum int
}

func parseYAML(data []byte) (any, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var lines []yamlLine
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()

		// Remove comments, taking care not to strip # inside quotes
		cleaned := stripComment(raw)
		if strings.TrimSpace(cleaned) == "" {
			continue
		}

		indent := countIndent(cleaned)
		trimmed := strings.TrimSpace(cleaned)
		lines = append(lines, yamlLine{
			indent:  indent,
			content: trimmed,
			lineNum: lineNum,
		})
	}

	if len(lines) == 0 {
		return map[string]any{}, nil
	}

	idx := 0
	val, nextIdx, err := parseBlock(lines, idx, lines[0].indent)
	if err != nil {
		return nil, err
	}
	_ = nextIdx
	return val, nil
}

func countIndent(s string) int {
	count := 0
	for _, ch := range s {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 2
		} else {
			break
		}
	}
	return count
}

func stripComment(s string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
		} else if ch == '"' && !inSingle {
			inDouble = !inDouble
		} else if ch == '#' && !inSingle && !inDouble {
			return s[:i]
		}
	}
	return s
}

func parseBlock(lines []yamlLine, idx int, currentIndent int) (any, int, error) {
	if idx >= len(lines) {
		return nil, idx, nil
	}

	first := lines[idx]
	if strings.HasPrefix(first.content, "-") {
		// It's a sequence/list
		return parseList(lines, idx, currentIndent)
	}
	// It's a mapping/dictionary
	return parseMap(lines, idx, currentIndent)
}

func parseMap(lines []yamlLine, idx int, currentIndent int) (map[string]any, int, error) {
	result := make(map[string]any)

	for idx < len(lines) {
		line := lines[idx]
		if line.indent < currentIndent {
			// Back out to outer indent
			break
		}
		if line.indent > currentIndent {
			return nil, idx, fmt.Errorf("line %d: unexpected indent", line.lineNum)
		}

		// Line format: key: [value]
		colonIdx := strings.Index(line.content, ":")
		if colonIdx == -1 {
			return nil, idx, fmt.Errorf("line %d: expected key-value mapping with ':'", line.lineNum)
		}

		key := strings.TrimSpace(line.content[:colonIdx])
		key = unquote(key)
		valStr := strings.TrimSpace(line.content[colonIdx+1:])

		idx++

		if valStr != "" {
			// Inline scalar value
			result[key] = parseScalar(valStr)
		} else {
			// Sub-block (map or list)
			if idx < len(lines) && lines[idx].indent > currentIndent {
				subIndent := lines[idx].indent
				subVal, nextIdx, err := parseBlock(lines, idx, subIndent)
				if err != nil {
					return nil, idx, err
				}
				result[key] = subVal
				idx = nextIdx
			} else {
				result[key] = nil
			}
		}
	}

	return result, idx, nil
}

func parseList(lines []yamlLine, idx int, currentIndent int) ([]any, int, error) {
	var result []any

	for idx < len(lines) {
		line := lines[idx]
		if line.indent < currentIndent {
			break
		}
		if line.indent > currentIndent {
			return nil, idx, fmt.Errorf("line %d: unexpected list indent", line.lineNum)
		}

		if !strings.HasPrefix(line.content, "-") {
			break
		}

		itemContent := strings.TrimSpace(strings.TrimPrefix(line.content, "-"))
		idx++

		if itemContent == "" {
			// Item defined on subsequent indented lines
			if idx < len(lines) && lines[idx].indent > currentIndent {
				subIndent := lines[idx].indent
				subVal, nextIdx, err := parseBlock(lines, idx, subIndent)
				if err != nil {
					return nil, idx, err
				}
				result = append(result, subVal)
				idx = nextIdx
			} else {
				result = append(result, nil)
			}
		} else if strings.Contains(itemContent, ":") {
			// List of maps: - key: value
			// Might also have additional keys indented beneath it
			colonIdx := strings.Index(itemContent, ":")
			firstKey := unquote(strings.TrimSpace(itemContent[:colonIdx]))
			firstValStr := strings.TrimSpace(itemContent[colonIdx+1:])

			itemMap := make(map[string]any)
			if firstValStr != "" {
				itemMap[firstKey] = parseScalar(firstValStr)
			} else {
				// Followed by indented block under this key
				if idx < len(lines) && lines[idx].indent > currentIndent+2 {
					subVal, nextIdx, err := parseBlock(lines, idx, lines[idx].indent)
					if err != nil {
						return nil, idx, err
					}
					itemMap[firstKey] = subVal
					idx = nextIdx
				} else {
					itemMap[firstKey] = nil
				}
			}

			// Read remaining keys belonging to this map item (indented deeper than '-')
			for idx < len(lines) {
				nextLine := lines[idx]
				if nextLine.indent <= currentIndent {
					break
				}
				if strings.HasPrefix(nextLine.content, "-") {
					break
				}
				cIdx := strings.Index(nextLine.content, ":")
				if cIdx == -1 {
					break
				}
				k := unquote(strings.TrimSpace(nextLine.content[:cIdx]))
				vStr := strings.TrimSpace(nextLine.content[cIdx+1:])
				idx++

				if vStr != "" {
					itemMap[k] = parseScalar(vStr)
				} else {
					if idx < len(lines) && lines[idx].indent > nextLine.indent {
						subVal, nextIdx, err := parseBlock(lines, idx, lines[idx].indent)
						if err != nil {
							return nil, idx, err
						}
						itemMap[k] = subVal
						idx = nextIdx
					} else {
						itemMap[k] = nil
					}
				}
			}
			result = append(result, itemMap)
		} else {
			// Plain scalar list item
			result = append(result, parseScalar(itemContent))
		}
	}

	return result, idx, nil
}

func parseScalar(val string) any {
	val = strings.TrimSpace(val)

	// Check quoted
	if (strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\"")) ||
		(strings.HasPrefix(val, "'") && strings.HasSuffix(val, "'")) {
		return unquote(val)
	}

	// Booleans
	lower := strings.ToLower(val)
	if lower == "true" || lower == "yes" || lower == "on" {
		return true
	}
	if lower == "false" || lower == "no" || lower == "off" {
		return false
	}
	if lower == "null" || lower == "~" {
		return nil
	}

	// Integers
	if intVal, err := strconv.ParseInt(val, 10, 64); err == nil {
		return intVal
	}

	// Floats
	if floatVal, err := strconv.ParseFloat(val, 64); err == nil {
		return floatVal
	}

	return val
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
