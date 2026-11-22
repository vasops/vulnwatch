#!/bin/sh
# With networkPolicy.cilium.enabled the plain NetworkPolicy must not have an
# egress rule without a destination: Cilium adds up both policies, so such a
# rule would open its ports to any address next to the host name list.
set -eu
chart=$(dirname "$0")/..
helm template ci "$chart" -f "$chart/ci/cilium-values.yaml" --show-only templates/networkpolicy.yaml |
	awk '
	function check() {
		if (rule != "" && !has_to) { print "destination-free egress rule: " rule; bad = 1 }
	}
	/^  egress:/ { egress = 1; next }
	egress && /^    - / { check(); rule = $0; has_to = 0; rules++ }
	egress && /^(    - |      )to:/ { has_to = 1 }
	END {
		check()
		if (!rules) { print "no egress rules rendered"; bad = 1 }
		if (!bad) print "cilium egress: every NetworkPolicy rule has a destination (" rules " rules)"
		exit bad
	}'
