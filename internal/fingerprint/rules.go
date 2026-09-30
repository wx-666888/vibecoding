package fingerprint

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
)

//go:embed default_rules.json
var embeddedDefaultRules []byte

type Rule struct {
	ID           string   `json:"id"`
	Priority     int      `json:"priority"`
	Pattern      string   `json:"pattern"`
	Protocol     string   `json:"protocol"`
	Product      string   `json:"product"`
	VersionGroup int      `json:"version_group"`
	Confidence   float64  `json:"confidence"`
	Ports        []int    `json:"ports,omitempty"`

	compiledRe *regexp.Regexp
}

type OSHint struct {
	Pattern string `json:"pattern"`
	Name    string `json:"name"`

	compiledRe *regexp.Regexp
}

type RuleSet struct {
	Rules   []Rule   `json:"rules"`
	OSHints []OSHint `json:"os_hints"`
}

// LoadRules loads rules from a file path. If path is empty or file not found, it falls back to embedded rules.
func LoadRules(path string) (*Engine, error) {
	var data []byte
	var err error

	if path != "" {
		data, err = os.ReadFile(path)
		if err != nil && os.IsNotExist(err) && len(embeddedDefaultRules) > 0 {
			data = embeddedDefaultRules
		} else if err != nil {
			return nil, fmt.Errorf("failed to read rules from %s: %w", path, err)
		}
	} else {
		data = embeddedDefaultRules
	}

	return LoadRulesFromBytes(data)
}

// LoadRulesFromBytes parses and compiles a RuleSet from raw bytes.
func LoadRulesFromBytes(data []byte) (*Engine, error) {
	var set RuleSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules: %w", err)
	}

	seenIDs := make(map[string]bool)
	for i := range set.Rules {
		r := &set.Rules[i]
		if r.ID == "" {
			return nil, fmt.Errorf("rule index %d has empty ID", i)
		}
		if seenIDs[r.ID] {
			return nil, fmt.Errorf("duplicate rule ID: %s", r.ID)
		}
		seenIDs[r.ID] = true

		if r.Confidence < 0 || r.Confidence > 1.0 {
			return nil, fmt.Errorf("rule %s has invalid confidence %f (must be 0.0-1.0)", r.ID, r.Confidence)
		}

		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile pattern for rule %s: %w", r.ID, err)
		}
		if r.VersionGroup > 0 && r.VersionGroup > re.NumSubexp() {
			return nil, fmt.Errorf("rule %s version_group %d exceeds capture groups %d", r.ID, r.VersionGroup, re.NumSubexp())
		}
		r.compiledRe = re
	}

	for i := range set.OSHints {
		h := &set.OSHints[i]
		re, err := regexp.Compile(h.Pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile pattern for os_hint %s: %w", h.Name, err)
		}
		h.compiledRe = re
	}

	// Sort rules descending by priority
	sort.SliceStable(set.Rules, func(i, j int) bool {
		return set.Rules[i].Priority > set.Rules[j].Priority
	})

	return &Engine{
		rules:   set.Rules,
		osHints: set.OSHints,
	}, nil
}
