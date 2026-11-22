package httpx

import (
	"net/url"
	"regexp"
	"strings"
)

const redacted = "xxxxx"

// RedactURL hides what may carry a credential: the userinfo password (or a
// lone user name, often a token), every query value and the fragment.
// Scheme, host, path and query keys stay for debugging.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid URL>"
	}
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			u.User = url.UserPassword(u.User.Username(), redacted)
		} else {
			u.User = url.User(redacted)
		}
	}
	if u.RawQuery != "" {
		params := strings.Split(u.RawQuery, "&")
		for i, p := range params {
			if k, _, ok := strings.Cut(p, "="); ok {
				params[i] = k + "=" + redacted
			}
		}
		u.RawQuery = strings.Join(params, "&")
	}
	u.ForceQuery = false
	u.Fragment, u.RawFragment = "", ""
	return u.String()
}

var urlInText = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)

// RedactText applies RedactURL to every URL in s, e.g. an error message.
func RedactText(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	return urlInText.ReplaceAllStringFunc(s, func(m string) string {
		// Punctuation after a URL in prose ("parse <url>: ...") stays.
		u := strings.TrimRight(m, ".,:;)")
		return RedactURL(u) + m[len(u):]
	})
}

// RedactError returns err with the URLs in its message redacted; errors.Is
// and errors.As still see the original chain.
func RedactError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if r := RedactText(msg); r != msg {
		return &redactedError{msg: r, err: err}
	}
	return err
}

type redactedError struct {
	msg string
	err error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.err }

// redactArgs redacts URLs in log key-value pairs (strings and errors).
func redactArgs(kv []any) []any {
	out := make([]any, len(kv))
	for i, v := range kv {
		switch x := v.(type) {
		case string:
			out[i] = RedactText(x)
		case error:
			out[i] = RedactText(x.Error())
		default:
			out[i] = v
		}
	}
	return out
}
