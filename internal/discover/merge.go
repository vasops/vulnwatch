package discover

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/match"
)

// StackNode finds the stack inside a file: the whole document, or the
// mapping under key (dotted, e.g. "stack" in a Helm values file). With an
// empty key, a document without products/helm but with a "stack" key is
// read as a values file.
func StackNode(doc *yaml.Node, key string) (*yaml.Node, error) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("not a YAML mapping")
	}
	n := doc.Content[0]
	if key == "" {
		_, p := mapGet(n, "products")
		_, h := mapGet(n, "helm")
		if _, s := mapGet(n, "stack"); p == nil && h == nil && s != nil {
			key = "stack"
		}
	}
	if key != "" {
		for _, k := range strings.Split(key, ".") {
			_, v := mapGet(n, k)
			if v == nil || v.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("%s: not found or not a mapping", key)
			}
			n = v
		}
	}
	if n.Style&yaml.FlowStyle != 0 || len(n.Content) == 0 {
		return nil, fmt.Errorf("the stack is empty or written in flow style; write it with stack discover first")
	}
	return n, nil
}

// Merge adds the discovered stack to an existing stack file and returns the
// new file content and what changed. It edits the text in place, so
// formatting and comments are kept. Nothing is removed: a stack may cover
// several clusters, and stack diff shows what is stale.
//
//   - helm: an entry with the same repo and chart gets the discovered
//     version, versions overrides and exposure; when the chart is listed in
//     several versions and none matches, a new entry is added.
//   - products: versions the declared stack (products and charts) already
//     allows are left alone. A single-version product is updated, a union
//     gets the new version added, a missing product is appended.
//   - exposure: internet is added where it isn't set; an explicit setting is kept.
//   - generated_at: set to the day of now (UTC), the inventory's date.
func Merge(cfg *config.Config, src []byte, key string, res *Result, declared map[string]match.Constraint, now time.Time) ([]byte, []string, error) {
	return MergeScope(cfg, src, key, nil, res, declared, now)
}

// MergeScope is Merge into a tenant's environment: scope is its path in
// the stack (tenants, acme, environments, prod). A missing environment (or
// tenant, or tenants) is added with the whole discovered stack.
func MergeScope(cfg *config.Config, src []byte, key string, scope []string, res *Result, declared map[string]match.Constraint, now time.Time) ([]byte, []string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, nil, err
	}
	st, err := StackNode(&doc, key)
	if err != nil {
		return nil, nil, err
	}
	if len(scope) > 0 {
		parent, rest, err := scopeNode(st, scope)
		if err != nil {
			return nil, nil, err
		}
		if len(rest) > 0 {
			out, err := addScope(src, parent, rest, res, now)
			if err != nil {
				return nil, nil, err
			}
			if err := validateMerged(cfg, out, key); err != nil {
				return nil, nil, err
			}
			return out, []string{fmt.Sprintf("%s: added from context %s", strings.Join(scope, "."), res.Context)}, nil
		}
		if parent.Style&yaml.FlowStyle != 0 || len(parent.Content) == 0 {
			return nil, nil, fmt.Errorf("%s is empty or written in flow style; can't merge into it", strings.Join(scope, "."))
		}
		st = parent
	}
	p := &patcher{lines: strings.Split(string(src), "\n"), inserts: map[int][]string{}}
	m := &merger{cfg: cfg, p: p, st: st, declared: declared}
	for _, e := range res.Helm {
		if err := m.helm(e); err != nil {
			return nil, nil, err
		}
	}
	for _, prod := range res.Products {
		if err := m.product(prod); err != nil {
			return nil, nil, err
		}
	}
	if res.OS != nil {
		if err := m.os(res.OS); err != nil {
			return nil, nil, err
		}
	}
	if err := m.generatedAt(generatedAt(now)); err != nil {
		return nil, nil, err
	}
	if err := m.flush(); err != nil {
		return nil, nil, err
	}
	out := p.bytes()
	if err := validateMerged(cfg, out, key); err != nil {
		return nil, nil, err
	}
	return out, m.changes, nil
}

// CheckScope refuses a tenant environment (tenants, acme, environments,
// prod) that is the file's local stack, its top-level tenant and
// environment: that one is merged without --tenant and --environment.
func CheckScope(src []byte, key string, scope []string) error {
	if len(scope) != 4 {
		return nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return err
	}
	st, err := StackNode(&doc, key)
	if err != nil {
		return err
	}
	if scalar(st, "tenant") == scope[1] && scalar(st, "environment") == scope[3] {
		return fmt.Errorf("%s/%s is this file's local stack (its top-level tenant and environment): merge it without --tenant and --environment", scope[1], scope[3])
	}
	return nil
}

// validateMerged checks that the result is still a valid stack, every
// tenant environment included.
func validateMerged(cfg *config.Config, out []byte, key string) error {
	var check yaml.Node
	if err := yaml.Unmarshal(out, &check); err != nil {
		return fmt.Errorf("merged file is not valid YAML (please report this): %w", err)
	}
	sn, err := StackNode(&check, key)
	if err != nil {
		return err
	}
	b, err := yaml.Marshal(sn)
	if err != nil {
		return err
	}
	stack, err := config.ParseStack(b)
	if err == nil {
		var errs []error
		for _, sc := range stack.Scopes() {
			if _, err := catalog.Resolve(cfg, sc.Stack); err != nil {
				errs = append(errs, err)
			}
		}
		err = errors.Join(errs...)
	}
	if err != nil {
		return fmt.Errorf("merged stack is invalid (please report this): %w", err)
	}
	return nil
}

// scopeNode walks scope from the stack: the deepest existing mapping, and
// the path below it that is missing.
func scopeNode(st *yaml.Node, scope []string) (*yaml.Node, []string, error) {
	n := st
	for i, k := range scope {
		_, v := mapGet(n, k)
		if v == nil {
			return n, scope[i:], nil
		}
		if v.Kind != yaml.MappingNode {
			return nil, nil, fmt.Errorf("%s: not a mapping", strings.Join(scope[:i+1], "."))
		}
		n = v
	}
	return n, nil, nil
}

// addScope appends the missing path (e.g. environments: prod:) to parent,
// with the discovered stack below it.
func addScope(src []byte, parent *yaml.Node, rest []string, res *Result, now time.Time) ([]byte, error) {
	if parent.Style&yaml.FlowStyle != 0 || len(parent.Content) == 0 {
		return nil, fmt.Errorf("line %d: the mapping to add %s to is empty or in flow style", parent.Line, rest[0])
	}
	body, err := renderBody(res, now)
	if err != nil {
		return nil, err
	}
	ind := parent.Content[0].Column - 1
	pad := func(n int) string { return strings.Repeat(" ", n) }
	var lines []string
	if len(rest) >= 3 {
		lines = append(lines, "") // a new tenants block or tenant: set it apart
	}
	for i, k := range rest {
		lines = append(lines, pad(ind+2*i)+k+":")
	}
	for _, l := range strings.Split(strings.TrimRight(string(body), "\n"), "\n") {
		if strings.TrimSpace(l) == "" {
			lines = append(lines, "")
			continue
		}
		lines = append(lines, pad(ind+2*len(rest))+l)
	}
	p := &patcher{lines: strings.Split(string(src), "\n"), inserts: map[int][]string{}}
	p.after(lastLine(parent)-1, lines...)
	return p.bytes(), nil
}

type merger struct {
	cfg      *config.Config
	p        *patcher
	st       *yaml.Node
	declared map[string]match.Constraint
	changes  []string
	newHelm  []string // lines for helm entries to append
	newProds []string
	newOS    []string
	newDate  string                  // a generated_at line to append
	flowAdds map[*yaml.Node][]string // additions to single-line flow mappings
	keyAdds  map[*yaml.Node][]string // lines to append to block mappings
}

func (m *merger) note(format string, args ...any) {
	m.changes = append(m.changes, fmt.Sprintf(format, args...))
}

func (m *merger) helm(e *HelmEntry) error {
	r := e.Release
	_, seq := mapGet(m.st, "helm")
	var same []*yaml.Node
	if seq != nil {
		for _, it := range seq.Content {
			if it.Kind != yaml.MappingNode {
				continue
			}
			if scalar(it, "chart") == r.Chart && strings.TrimSuffix(scalar(it, "repo"), "/") == strings.TrimSuffix(r.Repo, "/") {
				same = append(same, it)
			}
		}
	}
	var target *yaml.Node
	switch {
	case len(same) == 1:
		target = same[0]
	case len(same) > 1:
		for _, it := range same {
			if scalar(it, "version") == r.Version {
				target = it
			}
		}
	}
	if target == nil {
		if len(same) > 1 {
			m.note("helm %s: added %s (also listed in other versions; remove the stale ones, see stack diff)", r.Chart, r.Version)
		} else {
			m.note("helm %s: added %s (%s)", r.Chart, r.Version, strings.Join(e.Origins, ", "))
		}
		m.newHelm = append(m.newHelm, helmLines(e)...)
		return nil
	}
	if _, v := mapGet(target, "version"); v != nil && v.Value != r.Version {
		if err := m.p.replace(v, formatScalar(r.Version, v.Style)); err != nil {
			return err
		}
		m.note("helm %s: %s -> %s", r.Chart, v.Value, r.Version)
	}
	_, vs := mapGet(target, "versions")
	var fresh []string
	for _, prod := range config.SortedKeys(r.Versions) {
		want := r.Versions[prod]
		if _, cur := mapGet(vs, prod); cur != nil {
			if cur.Value != want {
				if err := m.p.replace(cur, formatScalar(want, cur.Style)); err != nil {
					return err
				}
				m.note("helm %s: versions.%s %s -> %s (%s)", r.Chart, prod, cur.Value, want, e.Overrides[prod])
			}
			continue
		}
		if vs != nil {
			if err := m.addKey(vs, prod, quote(want)); err != nil {
				return err
			}
		} else {
			fresh = append(fresh, prod+": "+quote(want))
		}
		m.note("helm %s: versions.%s = %s (%s)", r.Chart, prod, want, e.Overrides[prod])
	}
	if len(fresh) > 0 {
		if err := m.addKey(target, "versions", "{ "+strings.Join(fresh, ", ")+" }"); err != nil {
			return err
		}
	}
	if e.ExposedBy != "" {
		if err := m.exposure(target, "helm "+r.Chart, e.ExposedBy); err != nil {
			return err
		}
	}
	return nil
}

func (m *merger) product(prod *Product) error {
	if c, ok := m.declared[prod.Name]; ok && allAllowed(c, prod.Versions) {
		if prod.ExposedBy != "" {
			if _, v := m.productEntry(prod.Name); v != nil {
				return m.productExposure(prod, v)
			}
		}
		return nil
	}
	k, v := m.productEntry(prod.Name)
	if v == nil {
		line := prod.Name + ": " + quote(strings.Join(prod.Versions, " || "))
		if prod.ExposedBy != "" {
			line = prod.Name + ": { version: " + quote(strings.Join(prod.Versions, " || ")) + ", exposure: internet }"
		}
		m.newProds = append(m.newProds, line+"  # "+comment(prod.Origins, prod.ExposedBy))
		m.note("products.%s: added %s (%s)", prod.Name, strings.Join(prod.Versions, " || "), comment(prod.Origins, ""))
		return nil
	}
	vn := v
	if v.Kind == yaml.MappingNode {
		_, vn = mapGet(v, "version")
	}
	if vn == nil || vn.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: products.%s has no version to update", k.Line, k.Value)
	}
	cur, err := match.ParseConstraint(vn.Value)
	if err != nil {
		return fmt.Errorf("line %d: products.%s: %w", k.Line, k.Value, err)
	}
	var next string
	if len(cur.Alternatives()) == 1 && !cur.Any() {
		vs := prod.Versions
		if !strings.HasPrefix(vn.Value, "v") {
			vs = nil
			for _, ver := range prod.Versions {
				vs = append(vs, strings.TrimPrefix(ver, "v")) // follow the file's spelling
			}
		}
		next = match.Union(vs...)
	} else {
		var missing []string
		for _, ver := range prod.Versions {
			if !cur.Allows(ver) {
				missing = append(missing, ver)
			}
		}
		next = match.Union(append([]string{vn.Value}, missing...)...)
	}
	if next != vn.Value {
		if v.Kind == yaml.ScalarNode && prod.ExposedBy != "" && !m.hasExposure(v) {
			if err := m.p.replace(vn, "{ version: "+quote(next)+", exposure: internet }"); err != nil {
				return err
			}
			m.note("products.%s: %s -> %s, exposure: internet (%s)", k.Value, vn.Value, next, prod.ExposedBy)
			return nil
		}
		if err := m.p.replace(vn, formatScalar(next, vn.Style)); err != nil {
			return err
		}
		m.note("products.%s: %s -> %s (%s)", k.Value, vn.Value, next, comment(prod.Origins, ""))
	}
	if prod.ExposedBy != "" {
		return m.productExposure(prod, v)
	}
	return nil
}

// os merges the nodes' OS. A new distribution or release replaces the
// kernel versions; otherwise they follow the product rules.
func (m *merger) os(o *config.StackOS) error {
	k, cur := mapGet(m.st, "os")
	if cur == nil {
		m.newOS = osLines(o)
		m.note("os: added %s %s, kernel %s", o.Name, o.Release, o.Kernel)
		return nil
	}
	if cur.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: os is not a mapping", k.Line)
	}
	changed := false
	for _, f := range [][2]string{{"name", o.Name}, {"release", o.Release}} {
		_, v := mapGet(cur, f[0])
		switch {
		case v == nil:
			if err := m.addKey(cur, f[0], quote(f[1])); err != nil {
				return err
			}
			changed = true
		case v.Value != f[1]:
			if err := m.p.replace(v, formatScalar(f[1], v.Style)); err != nil {
				return err
			}
			m.note("os.%s: %s -> %s", f[0], v.Value, f[1])
			changed = true
		}
	}
	_, kv := mapGet(cur, "kernel")
	switch {
	case kv == nil:
		if err := m.addKey(cur, "kernel", quote(o.Kernel)); err != nil {
			return err
		}
		m.note("os.kernel: %s", o.Kernel)
	case changed:
		if err := m.p.replace(kv, formatScalar(o.Kernel, kv.Style)); err != nil {
			return err
		}
		m.note("os.kernel: %s -> %s", kv.Value, o.Kernel)
	default:
		versions := strings.Split(o.Kernel, " || ")
		if c, ok := m.declared[catalog.KernelProduct(o)]; ok && allAllowed(c, versions) {
			break
		}
		cur, err := match.ParseConstraint(kv.Value)
		if err != nil {
			return fmt.Errorf("line %d: os.kernel: %w", kv.Line, err)
		}
		next := o.Kernel
		if len(cur.Alternatives()) > 1 {
			var missing []string
			for _, v := range versions {
				if !cur.Allows(v) {
					missing = append(missing, v)
				}
			}
			next = match.Union(append([]string{kv.Value}, missing...)...)
		}
		if next != kv.Value {
			if err := m.p.replace(kv, formatScalar(next, kv.Style)); err != nil {
				return err
			}
			m.note("os.kernel: %s -> %s", kv.Value, next)
		}
	}
	if o.KernelPackage != "" {
		if _, v := mapGet(cur, "kernel_package"); v == nil {
			if err := m.addKey(cur, "kernel_package", o.KernelPackage); err != nil {
				return err
			}
			m.note("os.kernel_package: %s", o.KernelPackage)
		}
	}
	return nil
}

// generatedAt dates the merged stack: its inventory is as of today,
// whatever else changed.
func (m *merger) generatedAt(date string) error {
	k, v := mapGet(m.st, "generated_at")
	switch {
	case v == nil:
		m.newDate = "generated_at: " + quote(date) + "  # " + generatedAtComment
		m.note("generated_at: %s", date)
	case v.Kind != yaml.ScalarNode:
		return fmt.Errorf("line %d: generated_at is not a date", k.Line)
	case v.Value != date:
		if err := m.p.replace(v, formatScalar(date, v.Style)); err != nil {
			return err
		}
		m.note("generated_at: %s -> %s", v.Value, date)
	}
	return nil
}

func osLines(o *config.StackOS) []string {
	lines := []string{"os:", "  name: " + o.Name, "  release: " + quote(o.Release), "  kernel: " + quote(o.Kernel)}
	if o.KernelPackage != "" {
		lines = append(lines, "  kernel_package: "+o.KernelPackage)
	}
	if o.Criticality != "" {
		lines = append(lines, "  criticality: "+o.Criticality+"  # every workload runs on the nodes")
	}
	return lines
}

func (m *merger) productExposure(prod *Product, v *yaml.Node) error {
	if v.Kind == yaml.ScalarNode {
		if err := m.p.replace(v, "{ version: "+formatScalar(v.Value, yaml.DoubleQuotedStyle)+", exposure: internet }"); err != nil {
			return err
		}
		m.note("products.%s: exposure: internet (%s)", prod.Name, prod.ExposedBy)
		return nil
	}
	return m.exposure(v, "products."+prod.Name, prod.ExposedBy)
}

func (m *merger) hasExposure(v *yaml.Node) bool {
	if v.Kind != yaml.MappingNode {
		return false
	}
	_, e := mapGet(v, "exposure")
	return e != nil
}

// exposure sets exposure: internet unless the entry sets it already.
func (m *merger) exposure(n *yaml.Node, what, reason string) error {
	if _, e := mapGet(n, "exposure"); e != nil {
		if e.Value != "internet" {
			m.note("note: %s: kept exposure %s, although it is reachable through %s", what, e.Value, reason)
		}
		return nil
	}
	if err := m.addKey(n, "exposure", "internet"); err != nil {
		return err
	}
	m.note("%s: exposure: internet (%s)", what, reason)
	return nil
}

// productEntry finds a product in the products map by name or alias.
func (m *merger) productEntry(name string) (*yaml.Node, *yaml.Node) {
	_, prods := mapGet(m.st, "products")
	if prods == nil {
		return nil, nil
	}
	for i := 0; i+1 < len(prods.Content); i += 2 {
		if canon, _, ok := catalog.Lookup(m.cfg, prods.Content[i].Value); ok && canon == name {
			return prods.Content[i], prods.Content[i+1]
		}
	}
	return nil, nil
}

// addKey adds key: value to a mapping, inline for a one-line flow mapping,
// as a new line for a block mapping.
func (m *merger) addKey(n *yaml.Node, key, value string) error {
	if n.Style&yaml.FlowStyle != 0 {
		if lastLine(n) != n.Line {
			return fmt.Errorf("line %d: can't add %s to a flow mapping spanning several lines; add it by hand", n.Line, key)
		}
		if m.flowAdds == nil {
			m.flowAdds = map[*yaml.Node][]string{}
		}
		m.flowAdds[n] = append(m.flowAdds[n], key+": "+value)
		return nil
	}
	if m.keyAdds == nil {
		m.keyAdds = map[*yaml.Node][]string{}
	}
	m.keyAdds[n] = append(m.keyAdds[n], key+": "+value)
	return nil
}

// flush turns the collected additions into text edits.
func (m *merger) flush() error {
	for _, n := range byLine(m.flowAdds) {
		adds := m.flowAdds[n]
		last := n.Content[len(n.Content)-1]
		line := []rune(m.p.lines[n.Line-1])
		start := last.Column - 1
		l, err := scalarLen(line, start, last)
		if err != nil {
			return err
		}
		i := start + l
		for i < len(line) && line[i] != '}' {
			i++
		}
		if i == len(line) {
			return fmt.Errorf("line %d: can't find the end of the flow mapping", n.Line)
		}
		if i > 0 && line[i-1] == ' ' {
			i-- // keep "{ a: 1 }" spacing
		}
		m.p.edits = append(m.p.edits, edit{n.Line - 1, i, 0, ", " + strings.Join(adds, ", ")})
	}
	// Inner mappings first: they may end on the same line as their parent.
	keyNodes := byLine(m.keyAdds)
	sort.SliceStable(keyNodes, func(i, j int) bool {
		li, lj := lastLine(keyNodes[i]), lastLine(keyNodes[j])
		if li != lj {
			return li < lj
		}
		return keyNodes[i].Column > keyNodes[j].Column
	})
	for _, n := range keyNodes {
		adds := m.keyAdds[n]
		ind := strings.Repeat(" ", n.Content[0].Column-1)
		var lines []string
		for _, a := range adds {
			lines = append(lines, ind+a)
		}
		m.p.after(lastLine(n)-1, lines...)
	}
	stInd := strings.Repeat(" ", m.st.Content[0].Column-1)
	if len(m.newProds) > 0 {
		k, prods := mapGet(m.st, "products")
		switch {
		case prods == nil:
			m.p.after(lastLine(m.st)-1, append([]string{"", stInd + "products:"}, prefix(m.newProds, stInd+"  ")...)...)
		case prods.Kind != yaml.MappingNode || prods.Style&yaml.FlowStyle != 0 || len(prods.Content) == 0:
			return fmt.Errorf("line %d: products is empty or in flow style; can't append to it", k.Line)
		default:
			ind := strings.Repeat(" ", prods.Content[0].Column-1)
			m.p.after(lastLine(prods)-1, prefix(m.newProds, ind)...)
		}
	}
	if len(m.newHelm) > 0 {
		k, seq := mapGet(m.st, "helm")
		switch {
		case seq == nil:
			m.p.after(lastLine(m.st)-1, append([]string{"", stInd + "helm:"}, indentHelm(m.newHelm, stInd+"  - ")...)...)
		case seq.Kind != yaml.SequenceNode || seq.Style&yaml.FlowStyle != 0 || len(seq.Content) == 0:
			return fmt.Errorf("line %d: helm is empty or in flow style; can't append to it", k.Line)
		default:
			first := seq.Content[0]
			line := []rune(m.p.lines[first.Line-1])
			dash := string(line[:first.Column-1]) // e.g. "  - "
			m.p.after(lastLine(seq)-1, indentHelm(m.newHelm, dash)...)
		}
	}
	if len(m.newOS) > 0 {
		m.p.after(lastLine(m.st)-1, append([]string{""}, prefix(m.newOS, stInd)...)...)
	}
	// Last: whatever was appended above belongs to the keys before it.
	if m.newDate != "" {
		m.p.after(lastLine(m.st)-1, stInd+m.newDate)
	}
	return nil
}

// helmLines renders a new helm entry; the first line goes after "- ".
func helmLines(e *HelmEntry) []string {
	r := e.Release
	origin := "  # " + strings.Join(e.Origins, "; ")
	if len(r.Versions) == 0 && e.ExposedBy == "" {
		return []string{"{ repo: " + r.Repo + ", chart: " + r.Chart + ", version: " + formatScalar(r.Version, 0) + " }" + origin}
	}
	lines := []string{"repo: " + r.Repo + origin, "chart: " + r.Chart, "version: " + formatScalar(r.Version, 0)}
	if len(r.Versions) > 0 {
		lines = append(lines, "versions:")
		for _, p := range config.SortedKeys(r.Versions) {
			l := "  " + p + ": " + quote(r.Versions[p])
			if c := e.Overrides[p]; c != "" {
				l += "  # " + c
			}
			lines = append(lines, l)
		}
	}
	if e.ExposedBy != "" {
		lines = append(lines, "exposure: internet  # "+e.ExposedBy)
	}
	return lines
}

// indentHelm indents helm entries from helmLines: an entry starts with "{"
// or "repo:" after the dash, its other lines align with the first key.
func indentHelm(lines []string, dash string) []string {
	cont := strings.Repeat(" ", len([]rune(dash)))
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, "{") || strings.HasPrefix(l, "repo:") {
			out = append(out, dash+l)
		} else {
			out = append(out, cont+l)
		}
	}
	return out
}

func prefix(lines []string, ind string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = ind + l
	}
	return out
}

// byLine returns the map's nodes in file order, so edits are deterministic.
func byLine(m map[*yaml.Node][]string) []*yaml.Node {
	nodes := make([]*yaml.Node, 0, len(m))
	for n := range m {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Line < nodes[j].Line || (nodes[i].Line == nodes[j].Line && nodes[i].Column < nodes[j].Column)
	})
	return nodes
}

func comment(origins []string, exposedBy string) string {
	c := origins
	if len(c) > 2 {
		c = append(slices.Clone(c[:2]), fmt.Sprintf("+%d more", len(origins)-2))
	}
	s := strings.Join(c, "; ")
	if exposedBy != "" {
		s += "; exposed by " + exposedBy
	}
	return s
}

func allAllowed(c match.Constraint, versions []string) bool {
	for _, v := range versions {
		if !c.Allows(v) {
			return false
		}
	}
	return true
}

func mapGet(n *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i], n.Content[i+1]
		}
	}
	return nil, nil
}

func scalar(n *yaml.Node, key string) string {
	if _, v := mapGet(n, key); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}

func lastLine(n *yaml.Node) int {
	l := n.Line
	for _, c := range n.Content {
		l = max(l, lastLine(c))
	}
	return l
}

var plainSafe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// formatScalar writes v in the given style; a plain scalar stays plain only
// when YAML reads it back as the same string (17.4 would become a number).
func formatScalar(v string, style yaml.Style) string {
	switch {
	case style&yaml.SingleQuotedStyle != 0:
		return "'" + strings.ReplaceAll(v, "'", "''") + "'"
	case style&yaml.DoubleQuotedStyle != 0:
		return quote(v)
	}
	if plainSafe.MatchString(v) {
		var got any
		if yaml.Unmarshal([]byte(v), &got) == nil {
			if s, ok := got.(string); ok && s == v {
				return v
			}
		}
	}
	return quote(v)
}

func quote(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// patcher applies edits to the source text.
type patcher struct {
	lines   []string
	edits   []edit
	inserts map[int][]string // lines to insert after a 0-based line
}

type edit struct {
	line, col, n int // 0-based line, rune column, runes replaced
	text         string
}

func (p *patcher) replace(n *yaml.Node, text string) error {
	line := []rune(p.lines[n.Line-1])
	l, err := scalarLen(line, n.Column-1, n)
	if err != nil {
		return err
	}
	p.edits = append(p.edits, edit{n.Line - 1, n.Column - 1, l, text})
	return nil
}

func (p *patcher) after(line int, text ...string) {
	p.inserts[line] = append(p.inserts[line], text...)
}

func (p *patcher) bytes() []byte {
	sort.SliceStable(p.edits, func(i, j int) bool {
		if p.edits[i].line != p.edits[j].line {
			return p.edits[i].line > p.edits[j].line
		}
		return p.edits[i].col > p.edits[j].col
	})
	for _, e := range p.edits {
		r := []rune(p.lines[e.line])
		p.lines[e.line] = string(r[:e.col]) + e.text + string(r[e.col+e.n:])
	}
	var buf bytes.Buffer
	for i, l := range p.lines {
		if i > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString(l)
		for _, ins := range p.inserts[i] {
			buf.WriteString("\n" + ins)
		}
	}
	return buf.Bytes()
}

// scalarLen is the length of a single-line scalar's source text at col.
func scalarLen(line []rune, col int, n *yaml.Node) (int, error) {
	if col < len(line) {
		switch {
		case n.Style&yaml.DoubleQuotedStyle != 0:
			for i := col + 1; i < len(line); i++ {
				if line[i] == '\\' {
					i++
					continue
				}
				if line[i] == '"' {
					return i - col + 1, nil
				}
			}
		case n.Style&yaml.SingleQuotedStyle != 0:
			for i := col + 1; i < len(line); i++ {
				if line[i] == '\'' {
					if i+1 < len(line) && line[i+1] == '\'' {
						i++
						continue
					}
					return i - col + 1, nil
				}
			}
		case n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) == 0:
			l := len([]rune(n.Value))
			if col+l <= len(line) && string(line[col:col+l]) == n.Value {
				return l, nil
			}
		}
	}
	return 0, fmt.Errorf("line %d: can't locate %q to edit it", n.Line, n.Value)
}
