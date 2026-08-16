package authz

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Permission struct {
	Action      string   `yaml:"action"`
	Namespaces  []string `yaml:"namespaces"`
	Deployments []string `yaml:"deployments"`
}

type RepositoryEntry struct {
	Repository   string       `yaml:"repository"`
	RepositoryID string       `yaml:"repository_id"`
	Permissions  []Permission `yaml:"permissions"`
}

type Policy struct {
	Version      int               `yaml:"version"`
	Repositories []RepositoryEntry `yaml:"repositories"`
}

func LoadPolicy(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d", p.Version)
	}
	return &p, nil
}

func matchList(list []string, value string) bool {
	for _, v := range list {
		if v == "*" || v == value {
			return true
		}
	}
	return false
}

func (p *Policy) Authorize(repo, repoID, action, namespace, deployment string) bool {
	for _, entry := range p.Repositories {
		if entry.Repository != repo || entry.RepositoryID != repoID {
			continue
		}
		for _, perm := range entry.Permissions {
			if perm.Action == action &&
				matchList(perm.Namespaces, namespace) &&
				matchList(perm.Deployments, deployment) {
				return true
			}
		}
	}
	return false
}
