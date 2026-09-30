package fingerprint

import (
	"strings"
)

type Engine struct {
	rules   []Rule
	osHints []OSHint
}

// Identify identifies a single Banner input.
func (e *Engine) Identify(input Input) Result {
	res := Result{
		IP:         input.IP,
		Port:       input.Port,
		Protocol:   "unknown",
		Product:    "",
		Version:    "",
		OSHint:     "",
		Confidence: 0.0,
	}

	banner := input.Banner
	if len(banner) == 0 {
		return res
	}

	// 1. First priority: MySQL handshake packet parsing
	if prod, ver, ok := parseMySQLHandshake(banner); ok {
		res.Protocol = "MySQL"
		res.Product = prod
		res.Version = ver
		res.Confidence = 0.90
		res.OSHint = e.matchOSHint(banner)
		return res
	}

	// Prepare raw decoded view for binary protocol matching (e.g. \x16\x03 TLS)
	rawBytes := decodeHexEscapes(banner)
	rawStr := string(rawBytes)

	// 2. Iterate rules by priority
	for _, rule := range e.rules {
		if len(rule.Ports) > 0 {
			portMatched := false
			for _, p := range rule.Ports {
				if p == input.Port {
					portMatched = true
					break
				}
			}
			if !portMatched {
				continue
			}
		}

		// Try matching on original banner and decoded banner
		sub := rule.compiledRe.FindStringSubmatch(banner)
		if sub == nil && rawStr != banner {
			sub = rule.compiledRe.FindStringSubmatch(rawStr)
		}

		if sub != nil {
			res.Protocol = rule.Protocol
			res.Product = rule.Product
			res.Confidence = rule.Confidence

			if rule.VersionGroup > 0 && rule.VersionGroup < len(sub) {
				res.Version = strings.TrimSpace(sub[rule.VersionGroup])
			}

			// In case product had no specific name but regex had a group (e.g. generic HTTP server)
			if res.Product == "" && rule.ID == "http-server-generic" && len(sub) > 1 {
				res.Product = strings.TrimSpace(sub[1])
			}

			res.OSHint = e.matchOSHint(banner)
			return res
		}
	}

	return res
}

// matchOSHint scans the banner for operating system markers.
func (e *Engine) matchOSHint(banner string) string {
	for _, hint := range e.osHints {
		if hint.compiledRe.MatchString(banner) {
			return hint.Name
		}
	}
	return ""
}

// IdentifyBatch identifies a slice of Banner inputs in order.
func (e *Engine) IdentifyBatch(inputs []Input) []Result {
	if len(inputs) == 0 {
		return []Result{}
	}

	results := make([]Result, len(inputs))
	for i, inp := range inputs {
		results[i] = e.Identify(inp)
	}
	return results
}
