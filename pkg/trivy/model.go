package trivy

import (
	"time"
)

const SchemaVersion = 2

type ScanReport struct {
	SchemaVersion int
	Results       []ScanResult `json:"Results"`
}

type ScanResult struct {
	Target string `json:"Target"`
	// Class tells apart the kinds of result Trivy groups under one target,
	// e.g. os-pkgs, lang-pkgs or secret.
	Class           string          `json:"Class"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
	Secrets         []Secret        `json:"Secrets"`
}

type Metadata struct {
	NextUpdate time.Time `json:"NextUpdate"`
	UpdatedAt  time.Time `json:"UpdatedAt"`
}

type VersionInfo struct {
	Version         string    `json:"Version,omitempty"`
	VulnerabilityDB *Metadata `json:"VulnerabilityDB"`
	JavaDB          *Metadata `json:"JavaDB"`
}

type Layer struct {
	Digest string `json:"Digest"`
	DiffID string `json:"DiffID"`
}

type CVSSInfo struct {
	V2Vector string   `json:"V2Vector,omitempty"`
	V3Vector string   `json:"V3Vector,omitempty"`
	V2Score  *float32 `json:"V2Score,omitempty"`
	V3Score  *float32 `json:"V3Score,omitempty"`
}

type Report struct {
	SBOM            any
	Vulnerabilities []Vulnerability
	Secrets         []SecretFinding
}

// Secret is a secret Trivy matched in a file of the scanned image.
//
// Trivy also reports a Code block holding the lines surrounding the match, which is
// deliberately not modelled here: Trivy redacts the secret only on the matching line,
// so Code.Lines carries the neighbouring file content verbatim and can expose further
// credentials. Only Match, which is redacted, is forwarded to Harbor.
type Secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	// Match is the matching line with the secret value replaced by asterisks.
	Match string `json:"Match"`
	// Layer is the layer that introduced the secret. For secrets Trivy fills DiffID and
	// CreatedBy but not Digest, so the digest reaching Harbor is empty.
	Layer *Layer `json:"Layer"`
}

// SecretFinding pairs a Secret with the file it was found in. Trivy reports that path
// once on the enclosing ScanResult rather than on each secret, as an absolute path
// inside the image filesystem, e.g. /app/config/.env
type SecretFinding struct {
	Secret
	Target string
}

type Vulnerability struct {
	VulnerabilityID  string              `json:"VulnerabilityID"`
	PkgName          string              `json:"PkgName"`
	InstalledVersion string              `json:"InstalledVersion"`
	Status           string              `json:"Status"`
	FixedVersion     string              `json:"FixedVersion"`
	Title            string              `json:"Title"`
	Description      string              `json:"Description"`
	Severity         string              `json:"Severity"`
	References       []string            `json:"References"`
	PrimaryURL       string              `json:"PrimaryURL"`
	Layer            *Layer              `json:"Layer"`
	CVSS             map[string]CVSSInfo `json:"CVSS"`
	CweIDs           []string            `json:"CweIDs"`
}
