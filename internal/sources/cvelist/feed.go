package cvelist

import (
	"archive/zip"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vasops/vulnwatch/internal/state"
)

const (
	maxArchive = 4 << 30 // bytes per downloaded or unpacked archive
	maxRecord  = 8 << 20 // bytes per record
	// maxCatchUp is how many days of deltas a run applies; an index that
	// is further behind is built again from the full dump.
	maxCatchUp = 30
	perPage    = 100 // releases per API request (about 4 days)
	maxPages   = 12
	dayLayout  = "2006-01-02"
)

// Release tags: cve_2026-11-12_1700Z (hourly: that day's dump and the
// changes since midnight), cve_2026-11-11_at_end_of_day (that day's changes).
var tagRe = regexp.MustCompile(`^cve_(\d{4}-\d{2}-\d{2})_(?:(\d{2})00Z|at_end_of_day)$`)

type release struct {
	Tag    string `json:"tag_name"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// feed is what the release list offers, per day (YYYY-MM-DD).
type feed struct {
	dump     map[string]string // the full dump at midnight
	endOfDay map[string]string // the changes of the whole day
	hourly   map[string]hourly // the latest changes since midnight
}

type hourly struct {
	hour int
	url  string
}

func (f feed) newestDump() string {
	newest := ""
	for d := range f.dump {
		newest = max(newest, d)
	}
	return newest
}

func (f feed) lastDay() string {
	last := ""
	for d := range f.endOfDay {
		last = max(last, d)
	}
	for d := range f.hourly {
		last = max(last, d)
	}
	return last
}

// releases lists the releases back to day from (inclusive), or with from
// "" back to the newest full dump. The list is newest first; a day's
// end-of-day release comes after its hourly ones.
func (s *Source) releases(ctx context.Context, from string) (feed, error) {
	f := feed{dump: map[string]string{}, endOfDay: map[string]string{}, hourly: map[string]hourly{}}
	u, err := url.Parse(s.cfg.ReleasesURL)
	if err != nil {
		return f, err
	}
	headers := map[string]string{}
	if s.token != "" && u.Host == "api.github.com" {
		headers["Authorization"] = "Bearer " + s.token
	}
	for page := 1; page <= maxPages; page++ {
		q := u.Query()
		q.Set("per_page", strconv.Itoa(perPage))
		q.Set("page", strconv.Itoa(page))
		u.RawQuery = q.Encode()
		var rs []release
		if _, err := s.client.GetJSON(ctx, u.String(), headers, &rs); err != nil {
			return f, fmt.Errorf("list releases: %w", err)
		}
		oldest := ""
		for _, r := range rs {
			m := tagRe.FindStringSubmatch(r.Tag)
			if m == nil {
				continue
			}
			day := m[1]
			if oldest == "" || day < oldest {
				oldest = day
			}
			for _, a := range r.Assets {
				switch {
				case strings.HasSuffix(a.Name, "_all_CVEs_at_midnight.zip.zip"):
					f.dump[day] = a.URL
				case !strings.Contains(a.Name, "_delta_CVEs_at_") || !strings.HasSuffix(a.Name, ".zip"):
				case m[2] == "":
					f.endOfDay[day] = a.URL
				default:
					h, _ := strconv.Atoi(m[2])
					if cur, ok := f.hourly[day]; !ok || h > cur.hour {
						f.hourly[day] = hourly{h, a.URL}
					}
				}
			}
		}
		start := from
		if start == "" {
			start = f.newestDump()
		}
		if len(rs) < perPage || (start != "" && oldest != "" && oldest < start) {
			return f, nil
		}
	}
	return f, fmt.Errorf("list releases: more than %d pages back to %s", maxPages, cmp.Or(from, "the newest full dump"))
}

// prepare brings the index up to date, once per run: on the first run (or
// when it is more than maxCatchUp days behind) from the full dump, then
// with the end-of-day changes of every day since the last applied one and
// the latest hourly changes of the days without them yet (today). The
// archives stay open for the run: matched records are read from them.
func (s *Source) prepare(ctx context.Context) error {
	if s.index == nil {
		return errors.New("cvelist needs the state DB (its match index)")
	}
	meta, err := s.index.CVEListMeta(ctx)
	if err != nil {
		return fmt.Errorf("read index: %w", err)
	}
	today := s.now().UTC().Format(dayLayout)
	applied, perr := time.Parse(dayLayout, meta.Applied)
	rebuild := meta.Baseline == "" || perr != nil || applied.AddDate(0, 0, maxCatchUp).Format(dayLayout) < today
	if rebuild && s.index.ReadOnly() {
		return errors.New("no current index: a run that writes the state builds it from the full CVE list (about 660 MB)")
	}
	if err := s.workDir(); err != nil {
		return err
	}
	from := ""
	if !rebuild {
		from = applied.AddDate(0, 0, 1).Format(dayLayout)
	}
	f, err := s.releases(ctx, from)
	if err != nil {
		return err
	}
	start := time.Now()
	if rebuild {
		day := f.newestDump()
		if day == "" {
			return errors.New("no release with the full dump")
		}
		if err := s.applyDump(ctx, f.dump[day], day); err != nil {
			return fmt.Errorf("full dump %s: %w", day, err)
		}
		d, _ := time.Parse(dayLayout, day)
		applied = d.AddDate(0, 0, -1)
	}
	n, days := 0, 0
	complete := true // every earlier day applied completely
	last := f.lastDay()
	for d := applied.AddDate(0, 0, 1); d.Format(dayLayout) <= last; d = d.AddDate(0, 0, 1) {
		day := d.Format(dayLayout)
		switch {
		case f.endOfDay[day] != "":
			done := ""
			if complete {
				done = day
			}
			k, err := s.applyDelta(ctx, f.endOfDay[day], day, done)
			if err != nil {
				return fmt.Errorf("changes of %s: %w", day, err)
			}
			n, days = n+k, days+1
		case f.hourly[day].url != "":
			// The day isn't over (or its end-of-day release not out yet):
			// its changes so far, applied again next run.
			complete = false
			k, err := s.applyDelta(ctx, f.hourly[day].url, fmt.Sprintf("%s-%02d", day, f.hourly[day].hour), "")
			if err != nil {
				return fmt.Errorf("changes of %s until %02d:00Z: %w", day, f.hourly[day].hour, err)
			}
			n, days = n+k, days+1
		default:
			complete = false
		}
	}
	s.log.Info("cvelist index updated", "deltas", days, "records", n, "read_only", s.index.ReadOnly(), "took", time.Since(start).Round(time.Second))
	return nil
}

// workDir creates this run's directory below work_dir, after removing
// what a crashed run left there.
func (s *Source) workDir() error {
	if err := os.MkdirAll(s.cfg.WorkDir, 0o700); err != nil {
		return fmt.Errorf("work dir: %w", err)
	}
	stale, _ := filepath.Glob(filepath.Join(s.cfg.WorkDir, "run-*"))
	for _, d := range stale {
		_ = os.RemoveAll(d)
	}
	dir, err := os.MkdirTemp(s.cfg.WorkDir, "run-")
	if err != nil {
		return fmt.Errorf("work dir: %w", err)
	}
	s.dir = dir
	return nil
}

// applyDump builds the index from the full dump of day: a zip holding a zip
// of every record. Only the inner zip is unpacked; records are read from it.
func (s *Source) applyDump(ctx context.Context, assetURL, day string) error {
	start := time.Now()
	outer := filepath.Join(s.dir, "dump.zip.zip")
	if err := s.download(ctx, assetURL, outer); err != nil {
		return err
	}
	inner := filepath.Join(s.dir, "dump.zip")
	if err := unpackInner(outer, inner); err != nil {
		return err
	}
	_ = os.Remove(outer)
	zr, err := s.open(inner)
	if err != nil {
		return err
	}
	u, err := s.index.UpdateCVEList(ctx, true)
	if err != nil {
		return err
	}
	defer u.Rollback()
	n, err := s.readArchive(ctx, zr, u, false)
	if err != nil {
		return err
	}
	prev, _ := time.Parse(dayLayout, day)
	if err := u.Commit(ctx, state.CVEListMeta{Baseline: day, Applied: prev.AddDate(0, 0, -1).Format(dayLayout)}); err != nil {
		return err
	}
	s.log.Info("cvelist index built from the full dump", "day", day, "records", n, "took", time.Since(start).Round(time.Second))
	return nil
}

// applyDelta applies one delta archive; done (YYYY-MM-DD) marks that day
// as applied completely. A read-only index only keeps it for this run.
func (s *Source) applyDelta(ctx context.Context, assetURL, name, done string) (int, error) {
	file := filepath.Join(s.dir, "delta-"+name+".zip")
	if err := s.download(ctx, assetURL, file); err != nil {
		return 0, err
	}
	zr, err := s.open(file)
	if err != nil {
		return 0, err
	}
	var u *state.CVEListUpdate
	if !s.index.ReadOnly() {
		if u, err = s.index.UpdateCVEList(ctx, false); err != nil {
			return 0, err
		}
		defer u.Rollback()
	}
	n, err := s.readArchive(ctx, zr, u, true)
	if err != nil || u == nil {
		return n, err
	}
	return n, u.Commit(ctx, state.CVEListMeta{Applied: done})
}

// readArchive indexes every record of an archive (u nil: read-only) and
// remembers where it is; delta records are also kept as this run's changes.
// A record that doesn't parse is skipped.
func (s *Source) readArchive(ctx context.Context, zr *zip.Reader, u *state.CVEListUpdate, delta bool) (int, error) {
	n, bad := 0, 0
	for _, zf := range zr.File {
		if !recordRe.MatchString(zf.Name) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return n, err
		}
		r, err := readRecord(zf)
		if err != nil {
			bad++
			s.log.Debug("cvelist record skipped", "file", zf.Name, "err", err)
			continue
		}
		e := r.entry()
		if !s.remember(zf, e, delta) {
			continue
		}
		if u != nil {
			if err := u.Put(ctx, e); err != nil {
				return n, fmt.Errorf("index %s: %w", e.ID, err)
			}
		}
		n++
	}
	if bad > 0 {
		s.log.Warn("cvelist records skipped: not a CVE record", "count", bad)
	}
	return n, nil
}

// remember keeps the newest copy of a record read this run; false when an
// archive applied earlier had a newer one.
func (s *Source) remember(zf *zip.File, e state.CVEListEntry, delta bool) bool {
	if cur, ok := s.files[e.ID]; ok && cur.updated.After(e.Updated) {
		return false
	}
	s.files[e.ID] = archived{zf, e.Updated}
	if delta {
		s.changed[e.ID] = e
	}
	return true
}

func readRecord(zf *zip.File) (*record, error) {
	if zf.UncompressedSize64 > maxRecord {
		return nil, fmt.Errorf("%s: larger than %d bytes", zf.Name, maxRecord)
	}
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxRecord))
	if err != nil {
		return nil, err
	}
	return decode(b)
}

// download saves an asset (browser_download_url: no API quota, no token).
func (s *Source) download(ctx context.Context, assetURL, file string) error {
	out, err := os.Create(file) //nolint:gosec // a fixed name in this run's work dir
	if err != nil {
		return err
	}
	if _, err := s.client.Download(ctx, assetURL, out, maxArchive); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// open opens an archive for the rest of the run.
func (s *Source) open(file string) (*zip.Reader, error) {
	zr, err := zip.OpenReader(file)
	if err != nil {
		return nil, err
	}
	s.closers = append(s.closers, zr)
	return &zr.Reader, nil
}

// unpackInner writes the zip inside the dump's outer zip to dst.
func unpackInner(outer, dst string) error {
	zr, err := zip.OpenReader(outer)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()
	for _, zf := range zr.File {
		if !strings.HasSuffix(strings.ToLower(zf.Name), ".zip") {
			continue
		}
		if zf.UncompressedSize64 > maxArchive {
			return fmt.Errorf("%s: larger than %d bytes", zf.Name, int64(maxArchive))
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		out, err := os.Create(dst) //nolint:gosec // a fixed name in this run's work dir
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(rc, maxArchive)); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	return errors.New("no zip inside the dump")
}
