package server

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	maxCatalogEntries  = 256
	maxCatalogCommands = 32
)

var (
	exactTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}\.[a-z0-9][a-z0-9._-]{0,63}$`)
	wildTypePattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}\.\*$`)
	commandPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)
)

// Allow is an optional write capability on a credential. A nil Allow preserves
// the role's existing access. A non-nil Allow is default-deny for appends:
// types must match, commands match only when the list is present, and refs
// match only when that list is present.
type Allow struct {
	Types    []string `json:"types,omitempty"`
	Commands []string `json:"commands,omitempty"`
	Refs     []string `json:"refs,omitempty"`
}

func roleSatisfies(have, minimum Role) bool {
	if have == RoleAdmin {
		return true
	}
	if minimum == RoleOperator || have == RoleOperator {
		return have == minimum
	}
	return have >= minimum
}

func validateAllow(allow *Allow) error {
	if allow == nil {
		return nil
	}
	namespaces := make(map[string]struct{})
	seenType := make(map[string]struct{})
	for i, pattern := range allow.Types {
		pattern = strings.TrimSpace(pattern)
		allow.Types[i] = pattern
		if err := validateTypePattern(pattern); err != nil {
			return fmt.Errorf("allow.types[%d]: %w", i, err)
		}
		if _, ok := seenType[pattern]; ok {
			return fmt.Errorf("allow.types[%d] duplicates %q", i, pattern)
		}
		seenType[pattern] = struct{}{}
		namespace, err := namespaceOf(pattern)
		if err != nil {
			return fmt.Errorf("allow.types[%d]: %w", i, err)
		}
		namespaces[namespace] = struct{}{}
	}
	if len(namespaces) > 1 {
		return fmt.Errorf("allow.types must stay inside one namespace")
	}
	if allow.Commands != nil && len(allow.Types) == 0 {
		return fmt.Errorf("allow.commands requires at least one allow.types pattern")
	}
	seenCommand := make(map[string]struct{})
	for i, command := range allow.Commands {
		command = strings.TrimSpace(command)
		allow.Commands[i] = command
		if err := validateCommand(command); err != nil {
			return fmt.Errorf("allow.commands[%d]: %w", i, err)
		}
		if _, ok := seenCommand[command]; ok {
			return fmt.Errorf("allow.commands[%d] duplicates %q", i, command)
		}
		seenCommand[command] = struct{}{}
	}
	seenRef := make(map[string]struct{})
	for i, pattern := range allow.Refs {
		pattern = strings.TrimSpace(pattern)
		allow.Refs[i] = pattern
		if err := validateRefPattern(pattern); err != nil {
			return fmt.Errorf("allow.refs[%d]: %w", i, err)
		}
		if _, ok := seenRef[pattern]; ok {
			return fmt.Errorf("allow.refs[%d] duplicates %q", i, pattern)
		}
		seenRef[pattern] = struct{}{}
	}
	return nil
}

func validateTypePattern(pattern string) error {
	if exactTypePattern.MatchString(pattern) || wildTypePattern.MatchString(pattern) {
		return nil
	}
	return fmt.Errorf("type pattern %q must be namespace.name or namespace.*", pattern)
}

func validateCatalogType(eventType string) error {
	if !exactTypePattern.MatchString(eventType) {
		return fmt.Errorf("type %q must be namespace.name", eventType)
	}
	return nil
}

func validateCommand(command string) error {
	if !commandPattern.MatchString(command) {
		return fmt.Errorf("command %q must be 1-64 letters, digits, spaces, dots, underscores, or hyphens", command)
	}
	return nil
}

func validateRefPattern(pattern string) error {
	if strings.Count(pattern, "*") > 1 || (strings.Contains(pattern, "*") && !strings.HasSuffix(pattern, "*")) {
		return fmt.Errorf("ref pattern %q must be an exact name or a prefix ending in *", pattern)
	}
	body := strings.TrimSuffix(pattern, "*")
	if body == "" || body == "." || body == ".." || strings.Contains(body, "..") || strings.ContainsAny(body, `/\\`) {
		return fmt.Errorf("ref pattern %q must be a file-safe name", pattern)
	}
	return nil
}

func namespaceOf(pattern string) (string, error) {
	namespace, _, ok := strings.Cut(pattern, ".")
	if !ok || namespace == "" || strings.Contains(namespace, "*") {
		return "", fmt.Errorf("type pattern %q must be namespace.name or namespace.*", pattern)
	}
	return namespace, nil
}

func typeAllowed(pattern, eventType string) bool {
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, ".*") + "."
		return strings.HasPrefix(eventType, prefix) && len(eventType) > len(prefix)
	}
	return pattern == eventType
}

func refAllowed(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(name, prefix) && len(name) > len(prefix)
	}
	return pattern == name
}

func (allow *Allow) authorizeAppend(eventType, command string) error {
	if allow == nil {
		return nil
	}
	matched := false
	for _, pattern := range allow.Types {
		if typeAllowed(pattern, eventType) {
			matched = true
			break
		}
	}
	if !matched {
		return fmt.Errorf("credential is not allowed to append type %q", eventType)
	}
	if allow.Commands == nil {
		return nil
	}
	for _, candidate := range allow.Commands {
		if candidate == command {
			return nil
		}
	}
	return fmt.Errorf("credential is not allowed to append command %q", command)
}

func (allow *Allow) authorizeRef(name string) error {
	if allow == nil || allow.Refs == nil {
		return nil
	}
	for _, pattern := range allow.Refs {
		if refAllowed(pattern, name) {
			return nil
		}
	}
	return fmt.Errorf("credential is not allowed to update ref %q", name)
}
