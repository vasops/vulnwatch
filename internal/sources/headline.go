package sources

import (
	"regexp"
	"strings"
)

// productIntro matches a sentence that only says what the product is
// ("Redis is an open source, in-memory database …", "containerd is an
// open-source container runtime."), the usual opening of NVD descriptions.
var productIntro = regexp.MustCompile(`^(?:The )?[\w][\w .+/()-]{0,60}? (?:is|are) (?:a|an|the|open[- ]source)\b`)

// flawWords mark a sentence that describes the flaw itself.
var flawWords = regexp.MustCompile(`(?i)vulnerab|attacker|exploit|flaw|\bbugs?\b|inject|overflow|denial of service|bypass|crafted|malicious|unauthori[sz]ed|arbitrary|leak|disclos`)

// Headline returns the first sentence of an advisory text that describes
// the flaw: markdown headings and a leading sentence that only describes
// the product are skipped (unless nothing else follows). Paragraphs are
// separated by blank lines; a sentence ends at ". ".
func Headline(s string) string {
	var sentences []string
	for _, para := range paragraphs(s) {
		for para != "" {
			i := strings.Index(para, ". ")
			if i < 0 {
				sentences = append(sentences, para)
				break
			}
			sentences = append(sentences, para[:i+1])
			para = para[i+2:]
		}
	}
	for i, st := range sentences {
		if i < len(sentences)-1 && isProductIntro(st) {
			continue
		}
		return st
	}
	return ""
}

func isProductIntro(s string) bool {
	subject, _, _ := strings.Cut(s, " ")
	switch strings.ToLower(subject) {
	case "there", "this", "it", "that":
		return false
	}
	return productIntro.MatchString(s) && !flawWords.MatchString(s)
}

// paragraphs splits text at blank lines and markdown headings, with the
// whitespace inside each paragraph collapsed.
func paragraphs(s string) []string {
	var out, cur []string
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.Join(strings.Fields(strings.Join(cur, " ")), " "))
			cur = nil
		}
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			flush()
			continue
		}
		cur = append(cur, line)
	}
	flush()
	return out
}
