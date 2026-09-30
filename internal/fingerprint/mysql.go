package fingerprint

import (
	"bytes"
	"strconv"
	"strings"
)

// decodeHexEscapes decodes literal \xNN and standard escape sequences (\n, \r, \t, \0) into raw bytes.
func decodeHexEscapes(s string) []byte {
	if !strings.Contains(s, `\`) {
		return []byte(s)
	}

	buf := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if i+1 < len(s) && s[i] == '\\' {
			if i+3 < len(s) && s[i+1] == 'x' {
				if b, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					buf = append(buf, byte(b))
					i += 4
					continue
				}
			}
			switch s[i+1] {
			case 'n':
				buf = append(buf, '\n')
				i += 2
				continue
			case 'r':
				buf = append(buf, '\r')
				i += 2
				continue
			case 't':
				buf = append(buf, '\t')
				i += 2
				continue
			case '0':
				buf = append(buf, 0x00)
				i += 2
				continue
			case '\\':
				buf = append(buf, '\\')
				i += 2
				continue
			}
		}
		buf = append(buf, s[i])
		i++
	}
	return buf
}

// parseMySQLHandshake parses MySQL / MariaDB initial handshake packet.
// Returns product, version, and whether recognition succeeded.
func parseMySQLHandshake(banner string) (product, version string, ok bool) {
	if len(banner) == 0 {
		return "", "", false
	}

	raw := decodeHexEscapes(banner)

	// Try standard packet: 3 bytes length + 1 byte seq + 1 byte proto(0x0A) + null-terminated version
	var verBytes []byte

	if len(raw) >= 5 && raw[4] == 0x0A {
		// Scan for next 0x00 starting from index 5
		idx := bytes.IndexByte(raw[5:], 0x00)
		if idx != -1 && idx > 0 && idx <= 64 {
			verBytes = raw[5 : 5+idx]
		}
	}

	// Try stripped packet: starting directly with 0x0A
	if len(verBytes) == 0 && len(raw) >= 2 && raw[0] == 0x0A {
		idx := bytes.IndexByte(raw[1:], 0x00)
		if idx != -1 && idx > 0 && idx <= 64 {
			verBytes = raw[1 : 1+idx]
		}
	}

	if len(verBytes) == 0 {
		return "", "", false
	}

	verStr := strings.TrimSpace(string(verBytes))
	// Basic sanity check: version should contain at least one digit
	hasDigit := false
	for i := 0; i < len(verStr); i++ {
		c := verStr[i]
		if c >= '0' && c <= '9' {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return "", "", false
	}

	// Distinguish MariaDB vs MySQL
	if strings.Contains(strings.ToLower(verStr), "mariadb") {
		product = "MariaDB"
		// Strip MySQL 5.5.5 replication compatibility prefix if present
		cleanVer := verStr
		if strings.HasPrefix(cleanVer, "5.5.5-") {
			cleanVer = strings.TrimPrefix(cleanVer, "5.5.5-")
		}
		return product, cleanVer, true
	}

	product = "MySQL"
	return product, verStr, true
}
