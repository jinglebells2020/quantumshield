package rules

import (
	"embed"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtinRules embed.FS

type Engine struct {
	rules    []Rule
	compiled map[string][]*CompiledPattern
	mu       sync.RWMutex
}

type CompiledPattern struct {
	Rule    *Rule
	Pattern *Pattern
	Regexps []*regexp.Regexp
}

func NewEngine() (*Engine, error) {
	e := &Engine{
		compiled: make(map[string][]*CompiledPattern),
	}

	entries, err := builtinRules.ReadDir("builtin")
	if err != nil {
		return nil, fmt.Errorf("reading builtin rules: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := builtinRules.ReadFile("builtin/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("reading rule file %s: %w", entry.Name(), err)
		}

		var rules []Rule
		decoder := yaml.NewDecoder(strings.NewReader(string(data)))
		for {
			var r Rule
			if err := decoder.Decode(&r); err != nil {
				break
			}
			if r.ID != "" {
				rules = append(rules, r)
			}
		}

		for i := range rules {
			e.rules = append(e.rules, rules[i])
			if err := e.compileRule(&e.rules[len(e.rules)-1]); err != nil {
				return nil, fmt.Errorf("compiling rule %s: %w", rules[i].ID, err)
			}
		}
	}

	return e, nil
}

func (e *Engine) compileRule(r *Rule) error {
	for i := range r.Patterns {
		p := &r.Patterns[i]
		cp := &CompiledPattern{
			Rule:    r,
			Pattern: p,
		}
		for _, pat := range p.Patterns {
			re, err := regexp.Compile(pat)
			if err != nil {
				return fmt.Errorf("pattern %q in rule %s: %w", pat, r.ID, err)
			}
			cp.Regexps = append(cp.Regexps, re)
		}
		e.compiled[p.Language] = append(e.compiled[p.Language], cp)
	}
	return nil
}

func (e *Engine) MatchLine(language, line string) []*CompiledPattern {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []*CompiledPattern
	patterns := e.compiled[language]
	for _, cp := range patterns {
		for _, re := range cp.Regexps {
			if re.MatchString(line) {
				matches = append(matches, cp)
				break
			}
		}
	}
	return matches
}

func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rules
}

func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

func (e *Engine) PatternsForLanguage(lang string) []*CompiledPattern {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.compiled[lang]
}
