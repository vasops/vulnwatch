package discover

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/match"
)

var (
	debianImage  = regexp.MustCompile(`^Debian GNU/Linux (\d+)`)
	ubuntuImage  = regexp.MustCompile(`^Ubuntu (\d+\.\d+)`)
	rhelImage    = regexp.MustCompile(`^Red Hat Enterprise Linux (\d+(?:\.\d+)?)(?: |$)`)
	rockyImage   = regexp.MustCompile(`^Rocky Linux (\d+(?:\.\d+)?)`)
	almaImage    = regexp.MustCompile(`^AlmaLinux (\d+(?:\.\d+)?)`)
	slesImage    = regexp.MustCompile(`^SUSE Linux Enterprise Server (\d+(?: SP\d+)?)`)
	leapImage    = regexp.MustCompile(`^openSUSE Leap (\d+\.\d+)`)
	debianKernel = regexp.MustCompile(`^(\d+\.\d+\.\d+)\+deb`)                   // 6.12.48+deb13-cloud-amd64 (Debian 13 and newer)
	ubuntuKernel = regexp.MustCompile(`^(\d+\.\d+\.\d+-\d+)-([a-z][a-z0-9-]*)$`) // 6.8.0-71-generic, 6.8.0-1020-aws
	rpmKernel    = regexp.MustCompile(`^(\d+\.\d+\.\d+-[0-9][0-9A-Za-z._]*?)\.(x86_64|aarch64|ppc64le|s390x)$`)
	suseKernel   = regexp.MustCompile(`^(\d+\.\d+\.\d+-[0-9.]+)-([a-z0-9]+)$`) // 6.4.0-150600.23.17-default
)

// genericUbuntuFlavours run the kernel built from the linux source package.
var genericUbuntuFlavours = []string{"generic", "lowlatency", "generic-64k", "virtual"}

// osOf identifies a node's distribution, release, kernel package (empty:
// the distribution's default) and kernel package version (empty: unknown).
func osOf(n Node) (name, release, pkg, version string, ok bool) {
	sub := func(re *regexp.Regexp, s string) []string { return re.FindStringSubmatch(s) }
	switch {
	case debianImage.MatchString(n.OSImage):
		name, release = "debian", sub(debianImage, n.OSImage)[1]
		if m := sub(debianKernel, n.Kernel); m != nil {
			version = m[1]
		}
	case ubuntuImage.MatchString(n.OSImage):
		name, release = "ubuntu", sub(ubuntuImage, n.OSImage)[1]
		if m := sub(ubuntuKernel, n.Kernel); m != nil {
			version = m[1]
			if !slices.Contains(genericUbuntuFlavours, m[2]) {
				pkg = "linux-" + m[2]
			}
		}
	case rhelImage.MatchString(n.OSImage), rockyImage.MatchString(n.OSImage), almaImage.MatchString(n.OSImage):
		for _, d := range []struct {
			name string
			re   *regexp.Regexp
		}{{"rhel", rhelImage}, {"rocky", rockyImage}, {"almalinux", almaImage}} {
			if m := sub(d.re, n.OSImage); m != nil {
				name, release = d.name, m[1]
			}
		}
		if m := sub(rpmKernel, n.Kernel); m != nil {
			version = m[1]
		}
	case slesImage.MatchString(n.OSImage), leapImage.MatchString(n.OSImage):
		if m := sub(slesImage, n.OSImage); m != nil {
			name, release = "sles", m[1]
		} else {
			name, release = "opensuse-leap", sub(leapImage, n.OSImage)[1]
		}
		if m := sub(suseKernel, n.Kernel); m != nil {
			version = m[1] + ".1" // the package release adds ".1" to uname's
			if m[2] != "default" {
				pkg = "kernel-" + m[2]
			}
		}
	default:
		return "", "", "", "", false
	}
	return name, release, pkg, version, true
}

// nodeOS reads the nodes' distribution, release and running kernel(s). The
// distribution most nodes run wins; nodes the trackers can't serve are
// returned as notes.
func nodeOS(nodes []Node) (*config.StackOS, []Note) {
	type key struct{ name, release, pkg string }
	count := map[key]int{}
	kernels := map[key][]string{}
	var notes []Note
	for _, n := range nodes {
		name, release, pkg, v, ok := osOf(n)
		if !ok {
			notes = append(notes, Note{What: fmt.Sprintf("OS %s, kernel %s (no security data)", n.OSImage, n.Kernel), Where: []string{"node " + n.Name}})
			continue
		}
		k := key{name, release, pkg}
		count[k]++
		if v == "" {
			notes = append(notes, Note{What: fmt.Sprintf("kernel %s: package version unknown, set os.kernel by hand (dpkg -l 'linux-image*')", n.Kernel), Where: []string{"node " + n.Name}})
			continue
		}
		kernels[k] = addVersion(kernels[k], v)
	}
	var best key
	for k, c := range count {
		if c > count[best] || (c == count[best] && k.name+k.release < best.name+best.release) {
			best = k
		}
	}
	if count[best] == 0 || len(kernels[best]) == 0 {
		return nil, notes
	}
	for k, c := range count {
		if k != best {
			notes = append(notes, Note{What: fmt.Sprintf("%d node(s) run %s %s, not %s %s; the stack has one os", c, k.name, k.release, best.name, best.release), Where: []string{"nodes"}})
		}
	}
	vs := kernels[best]
	slices.SortFunc(vs, func(a, b string) int {
		va, ea := match.ParseVersion(a)
		vb, eb := match.ParseVersion(b)
		if ea != nil || eb != nil {
			return strings.Compare(a, b)
		}
		return va.Compare(vb)
	})
	o := &config.StackOS{Name: best.name, Release: best.release, Kernel: strings.Join(vs, " || "), Criticality: "high"}
	o.KernelPackage = best.pkg
	return o, notes
}

// addOS records the nodes' OS in the result.
func addOS(res *Result, nodes []Node) {
	o, notes := nodeOS(nodes)
	res.Unmapped = append(res.Unmapped, notes...)
	if o == nil {
		return
	}
	res.OS = o
	for _, v := range strings.Split(o.Kernel, " || ") {
		res.Observed[catalog.KernelProduct(o)] = addVersion(res.Observed[catalog.KernelProduct(o)], v)
	}
}
