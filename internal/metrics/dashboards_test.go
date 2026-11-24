package metrics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var dashboardFiles = []string{"vulnwatch.json", "vulnwatch-overview.json"}

type dashPanel struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Title   string `json:"title"`
	GridPos struct {
		X, Y, W, H int
	} `json:"gridPos"`
	Targets []struct {
		Expr string `json:"expr"`
	} `json:"targets"`
	Transformations []struct {
		ID      string `json:"id"`
		Options struct {
			RenameByName map[string]string `json:"renameByName"`
			IndexByName  map[string]int    `json:"indexByName"`
		} `json:"options"`
	} `json:"transformations"`
}

func loadDashboard(t *testing.T, name string) []dashPanel {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "charts", "vulnwatch", "dashboards", name))
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b) {
		t.Fatalf("%s is not valid JSON", name)
	}
	var d struct {
		Panels []dashPanel `json:"panels"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return d.Panels
}

var byClause = regexp.MustCompile(`by \(([^)]*)\)`)

func byLabels(clause string) []string {
	var out []string
	for _, l := range strings.Split(clause, ",") {
		out = append(out, strings.TrimSpace(l))
	}
	return out
}

// Scenario: dashboardy znají nový label. Both dashboards are valid JSON and
// every query over first_reported that lists kev in by (...) lists
// public_exploit there too.
func TestDashboardsKnowPublicExploitLabel(t *testing.T) {
	for _, name := range dashboardFiles {
		t.Run(name, func(t *testing.T) {
			n := 0
			for _, p := range loadDashboard(t, name) {
				for _, tg := range p.Targets {
					if !strings.Contains(tg.Expr, "vulnwatch_finding_first_reported_timestamp_seconds") {
						continue
					}
					for _, m := range byClause.FindAllStringSubmatch(tg.Expr, -1) {
						ls := byLabels(m[1])
						if !slices.Contains(ls, "kev") {
							continue
						}
						n++
						if !slices.Contains(ls, "public_exploit") {
							t.Errorf("panel %d %q: by (%s) lists kev but not public_exploit", p.ID, p.Title, m[1])
						}
					}
				}
			}
			if n == 0 {
				t.Fatal("no first_reported query listing kev: the finding tables are gone")
			}
		})
	}
}

// Every finding table with a KEV column has a public exploit column next to
// it (renamed, and placed right after KEV when the columns are ordered).
func TestFindingTablesHavePublicExploitColumn(t *testing.T) {
	for _, name := range dashboardFiles {
		t.Run(name, func(t *testing.T) {
			tables := 0
			for _, p := range loadDashboard(t, name) {
				if p.Type != "table" {
					continue
				}
				for _, tr := range p.Transformations {
					o := tr.Options
					if _, ok := o.RenameByName["kev"]; !ok {
						continue
					}
					tables++
					if o.RenameByName["public_exploit"] == "" {
						t.Errorf("panel %d %q: KEV column but no public_exploit column", p.ID, p.Title)
					}
					if kev, ok := o.IndexByName["kev"]; ok {
						if idx, ok := o.IndexByName["public_exploit"]; !ok || idx != kev+1 {
							t.Errorf("panel %d %q: public_exploit column at %d (present %v), want %d (right after KEV)", p.ID, p.Title, idx, ok, kev+1)
						}
					}
				}
			}
			if tables == 0 {
				t.Fatal("no table with a KEV column")
			}
		})
	}
}

// The status row: a stat panel over findings_open_public_exploit shares the
// former KEV slot with the KEV panel; both get short titles.
func TestDashboardsHavePublicExploitStat(t *testing.T) {
	kevSlotX := map[string]int{"vulnwatch.json": 16, "vulnwatch-overview.json": 12}
	for _, name := range dashboardFiles {
		t.Run(name, func(t *testing.T) {
			var kev, exploit *dashPanel
			panels := loadDashboard(t, name)
			for i, p := range panels {
				if p.Type != "stat" {
					continue
				}
				for _, tg := range p.Targets {
					switch {
					case strings.Contains(tg.Expr, "vulnwatch_findings_open_public_exploit"):
						exploit = &panels[i]
					case strings.Contains(tg.Expr, "vulnwatch_findings_open_kev"):
						kev = &panels[i]
					}
				}
			}
			if kev == nil || exploit == nil {
				t.Fatalf("want stat panels over findings_open_kev and findings_open_public_exploit: kev=%v exploit=%v", kev != nil, exploit != nil)
			}
			if kev.Title != "KEV" || exploit.Title != "Public exploit" {
				t.Errorf("titles %q and %q, want \"KEV\" and \"Public exploit\"", kev.Title, exploit.Title)
			}
			k, e := kev.GridPos, exploit.GridPos
			x := kevSlotX[name]
			if k.Y != 1 || e.Y != 1 || k.H != 4 || e.H != 4 || k.W+e.W != 4 || min(k.X, e.X) != x || max(k.X+k.W, e.X+e.W) != x+4 {
				t.Errorf("KEV %+v and public exploit %+v must split the former KEV slot x=%d..%d, y=1, h=4", k, e, x, x+4)
			}
			ids := map[int]bool{}
			for _, p := range panels {
				if ids[p.ID] {
					t.Errorf("duplicate panel id %d", p.ID)
				}
				ids[p.ID] = true
			}
		})
	}
}
