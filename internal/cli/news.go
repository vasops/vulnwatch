package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/news"
	slackout "github.com/vasops/vulnwatch/internal/output/slack"
	"github.com/vasops/vulnwatch/internal/state"
	"github.com/vasops/vulnwatch/version"
)

// newsDeadline bounds one news check: a few feed requests, the stack's
// charts (cached after the first check) and a few Slack posts.
const newsDeadline = 5 * time.Minute

var newsOutputNames = []string{"stdout", "slack"}

func newNewsCmd(a *app) *cobra.Command {
	var (
		outputs string
		dryRun  bool
		repost  int
	)
	cmd := &cobra.Command{
		Use:   "news",
		Short: "Post new items of the security news feeds (sources.news) once, with the stack products they name",
		Long: `Reads the feeds in sources.news (Red Hat's security bulletins, CERT-EU's advisories)
and posts each item not posted before, marked with the stack products its
title names and where they run. Meant to run often (hourly), next to the
daily run. A feed read for the first time is only remembered: nothing is
posted for what was already there. The state DB keeps what was posted.

--repost N posts the newest N items of each feed again, posted before or
not, on every check while it is set: to see the first messages in the
channel, then turn it off.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.news(cmd.Context(), outputs, dryRun, repost)
		},
	}
	cmd.Flags().StringVar(&outputs, "output", "stdout", "comma-separated outputs: stdout,slack")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "no state writes and no Slack")
	cmd.Flags().IntVar(&repost, "repost", 0, "post the newest N items of each feed again, posted before or not (to check the channel)")
	return cmd
}

func (a *app) news(ctx context.Context, outputs string, dryRun bool, repost int) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	if !cfg.Sources.News.Enabled || len(cfg.Sources.News.Feeds) == 0 {
		return errors.New("sources.news is disabled or has no feeds")
	}
	if repost < 0 {
		return errors.New("--repost: want 0 or more")
	}
	names := splitList(outputs)
	if len(names) == 0 {
		return errors.New("--output: at least one output is required")
	}
	for _, n := range names {
		if !slices.Contains(newsOutputNames, n) {
			return fmt.Errorf("--output: unknown output %q (want %v)", n, newsOutputNames)
		}
	}
	var sl *slackout.Output
	if slices.Contains(names, "slack") && !dryRun {
		sc := cfg.Outputs.Slack
		sl, err = slackout.New(sc, slackout.Settings{
			Token:       a.getenv(sc.TokenEnv),
			Channel:     a.getenv(sc.ChannelEnv),
			NewsChannel: a.getenv(sc.NewsChannelEnv),
		}, httpx.Plain(cfg.HTTP.Timeout.D()), a.log)
		if err != nil {
			return err
		}
	}
	if err := a.restrict(cfg, outputFlags{}); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, newsDeadline)
	defer cancel()
	store, err := state.Open(ctx, a.stateDB, dryRun)
	if err != nil {
		return err
	}
	defer store.Close()
	// The stack only marks the items with the products they name; the
	// news are posted without it too.
	products, err := a.loadProducts(ctx, cfg, store, nil)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		a.log.Warn("stack not loaded: news are posted without the products they name", "err", err)
	}
	n := newsRun{
		client: httpx.New(cfg.HTTP, version.Version, a.log), store: store, matcher: news.NewMatcher(products),
		slack: sl, stdout: slices.Contains(names, "stdout"), repost: repost, app: a,
	}
	var errs []error
	for _, f := range cfg.Sources.News.Feeds {
		if err := n.feed(ctx, f); err != nil {
			if ctx.Err() != nil {
				return errors.Join(append(errs, err)...)
			}
			a.log.Error("news feed failed", "feed", f.Name, "err", httpx.RedactError(err))
			errs = append(errs, fmt.Errorf("%s: %w", f.Name, err))
		}
	}
	return errors.Join(errs...)
}

type newsRun struct {
	client  *httpx.Client
	store   *state.Store
	matcher *news.Matcher
	slack   *slackout.Output
	stdout  bool
	repost  int // the newest items of each feed posted again
	app     *app
}

// feed handles one feed: new items (and the newest n.repost) oldest first,
// each remembered once it is posted, so a failed post is tried again by
// the next check.
func (n newsRun) feed(ctx context.Context, f config.NewsFeed) error {
	items, err := news.Fetch(ctx, n.client, f)
	if err != nil {
		return err
	}
	seen, err := n.store.NewsSeen(ctx, f.Name)
	if err != nil {
		return err
	}
	now := time.Now()
	if len(seen) == 0 {
		ids := make([]string, len(items))
		for i, it := range items {
			ids[i] = it.ID
		}
		n.app.log.Info("news feed read for the first time: its items are remembered, not posted", "feed", f.Name, "items", len(items))
		if err := n.store.MarkNewsSeen(ctx, f.Name, ids, now); err != nil || n.repost == 0 {
			return err
		}
		for _, id := range ids {
			seen[id] = true
		}
	}
	repost := map[string]bool{} // feeds list the newest first
	for _, it := range items[:min(n.repost, len(items))] {
		repost[it.ID] = true
	}
	posted, reposted := 0, 0
	var errs []error
	for _, it := range slices.Backward(items) {
		again := seen[it.ID]
		if again && !repost[it.ID] {
			continue
		}
		seen[it.ID] = true
		hits := n.matcher.Match(it.Title)
		if n.stdout {
			n.print(it, hits)
		}
		if n.slack != nil {
			if err := n.slack.PostNews(ctx, it, hits); err != nil {
				errs = append(errs, err)
				if ctx.Err() != nil {
					break
				}
				continue
			}
		}
		if err := n.store.MarkNewsSeen(ctx, f.Name, []string{it.ID}, now); err != nil {
			return errors.Join(append(errs, err)...)
		}
		posted++
		if again {
			reposted++
		}
	}
	n.app.log.Info("news feed checked", "feed", f.Name, "items", len(items), "new", posted-reposted, "reposted", reposted)
	return errors.Join(errs...)
}

func (n newsRun) print(it news.Item, hits []news.Hit) {
	w := n.app.stdout
	fmt.Fprintf(w, "%s · %s\n", it.Feed, it.Title)
	if it.Link != "" {
		fmt.Fprintf(w, "  %s\n", it.Link)
	}
	for _, h := range hits {
		scopes := make([]string, len(h.Scopes))
		for i, s := range h.Scopes {
			scopes[i] = s.String()
		}
		fmt.Fprintf(w, "  runs here: %s (%s)\n", h.Product, strings.Join(scopes, ", "))
	}
}
