package slack

import (
	"context"
	"fmt"
	"strings"

	"github.com/slack-go/slack"

	"github.com/vasops/vulnwatch/internal/logx"
	"github.com/vasops/vulnwatch/internal/news"
)

// maxNewsCVEs is how many CVE IDs a news message lists.
const maxNewsCVEs = 5

// PostNews posts one security news item to the news channel, with the
// stack products its title names and where they run.
func (o *Output) PostNews(ctx context.Context, it news.Item, hits []news.Hit) error {
	text := "Security news: " + it.Title
	if err := o.post(ctx, o.newsChannel, text, newsBlocks(it, hits, o.maxText())); err != nil {
		return fmt.Errorf("slack news %s %s: %w", o.newsChannel, it.ID, err)
	}
	logx.Audit(ctx, o.log, "slack message posted", "kind", "news", "channel", o.newsChannel, "feed", it.Feed, "id", it.ID, "text", it.Title)
	return nil
}

func newsBlocks(it news.Item, hits []news.Hit, maxText int) []slack.Block {
	lines := []string{":newspaper: *" + linkTo(it.Link, it.Title) + "*"}
	meta := "_" + escape(it.Feed) + "_"
	if !it.Published.IsZero() {
		meta += " · " + it.Published.UTC().Format("2 Jan 2006")
	}
	if n := len(it.CVEs); n > 0 {
		meta += " · " + strings.Join(it.CVEs[:min(n, maxNewsCVEs)], ", ")
		if n > maxNewsCVEs {
			meta += fmt.Sprintf(" +%d more", n-maxNewsCVEs)
		}
	}
	lines = append(lines, meta)
	if len(hits) > 0 {
		parts := make([]string, len(hits))
		for i, h := range hits {
			scopes := make([][2]string, len(h.Scopes))
			for j, s := range h.Scopes {
				scopes[j] = [2]string{s.Tenant, s.Environment}
			}
			parts[i] = "*" + escape(h.Product) + "* (" + escape(scopeList(scopes)) + ")"
		}
		lines = append(lines, ":round_pushpin: *Runs here:* "+strings.Join(parts, " · "))
	}
	return []slack.Block{slack.NewSectionBlock(mrkdwn(truncate(strings.Join(lines, "\n"), maxText)), nil, nil)}
}
