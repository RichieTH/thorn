package rules

import "path/filepath"

type DotEnvCommitted struct{}

func (DotEnvCommitted) ID() string         { return "ENV001" }
func (DotEnvCommitted) Name() string       { return ".env file committed to repo" }
func (DotEnvCommitted) Severity() Severity { return High }
func (r DotEnvCommitted) Scan(path, _ string) []Finding {
	if filepath.Base(path) == ".env" {
		return []Finding{findingAt(r, relFile(path), 1)}
	}
	return nil
}

type DotEnvProductionCommitted struct{}

func (DotEnvProductionCommitted) ID() string         { return "ENV002" }
func (DotEnvProductionCommitted) Name() string       { return ".env.production committed" }
func (DotEnvProductionCommitted) Severity() Severity { return Critical }
func (r DotEnvProductionCommitted) Scan(path, _ string) []Finding {
	if filepath.Base(path) == ".env.production" {
		return []Finding{findingAt(r, relFile(path), 1)}
	}
	return nil
}
