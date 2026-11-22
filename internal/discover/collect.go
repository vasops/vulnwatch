// Package discover reads what runs in a Kubernetes cluster (Argo CD
// Applications, Helm releases, container images, node components) and turns
// it into a stack.yaml.
package discover

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/vasops/vulnwatch/internal/helmchart"
	"github.com/vasops/vulnwatch/internal/imageref"
	"github.com/vasops/vulnwatch/internal/kube"
)

// Inventory is what was read from the cluster.
type Inventory struct {
	Context       string
	ServerVersion string // API server gitVersion, e.g. v1.34.2+rke2r1
	Nodes         []Node
	Apps          []App
	Releases      []Release
	Workloads     []Workload
	Warnings      []string
}

// Node is one node's component versions.
type Node struct {
	Name, Kubelet, Runtime string
	OSImage, Kernel        string // e.g. "Debian GNU/Linux 13 (trixie)", "6.12.48+deb13-cloud-amd64"
}

// App is one Helm chart source of an Argo CD Application.
type App struct {
	Name        string
	Namespace   string // destination namespace
	Repo        string // https://… or oci://…
	Chart       string
	Version     string
	ReleaseName string
	External    bool // deploys to another cluster
}

// Release is a Helm release stored in the cluster (helm install/upgrade).
type Release struct {
	Name, Namespace string
	Chart           *helmchart.Chart // values merged with the release's values
}

// Workload is one image run by one owner (Deployment, StatefulSet,
// DaemonSet, CronJob, operator-managed pods).
type Workload struct {
	Namespace string
	Owner     string // e.g. Deployment/keycloak
	Image     imageref.Ref
	Pods      int
	Exposed   string // how it is reachable from outside; empty if it is not
}

// Collect reads the inventory. Pods, nodes and the server version are
// required; Argo CD, Helm releases, CronJobs and routes are read when the
// API exists and the credentials allow it (otherwise a warning).
func Collect(ctx context.Context, c *kube.Client) (*Inventory, error) {
	inv := &Inventory{Context: c.Context}
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := c.Get(ctx, "/version", &v); err != nil {
		return nil, err
	}
	inv.ServerVersion = v.GitVersion

	nodes, err := kube.List[node](ctx, c, "/api/v1/nodes", "", 200)
	if err != nil {
		return nil, fmt.Errorf("nodes: %w", err)
	}
	for _, n := range nodes {
		ni := n.Status.NodeInfo
		inv.Nodes = append(inv.Nodes, Node{n.Metadata.Name, ni.KubeletVersion, ni.ContainerRuntimeVersion, ni.OSImage, ni.KernelVersion})
	}

	pods, err := kube.List[pod](ctx, c, "/api/v1/pods", "", 500)
	if err != nil {
		return nil, fmt.Errorf("pods: %w", err)
	}
	optional := func(what string, err error) bool {
		switch {
		case err == nil:
			return true
		case errors.Is(err, kube.ErrNotFound):
		case errors.Is(err, kube.ErrForbidden):
			inv.Warnings = append(inv.Warnings, what+": not allowed to read, skipped")
		default:
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("%s: %v", what, err))
		}
		return false
	}
	cronJobs, err := kube.List[cronJob](ctx, c, "/apis/batch/v1/cronjobs", "", 200)
	optional("cronjobs", err)

	exposed := map[string]string{} // namespace/service -> reason
	services, err := kube.List[service](ctx, c, "/api/v1/services", "", 500)
	if optional("services", err) {
		for _, s := range services {
			if t := s.Spec.Type; t == "LoadBalancer" || t == "NodePort" {
				exposed[s.Metadata.Namespace+"/"+s.Metadata.Name] = t + " service " + s.Metadata.Name
			}
		}
	}
	ingresses, err := kube.List[ingress](ctx, c, "/apis/networking.k8s.io/v1/ingresses", "", 500)
	if optional("ingresses", err) {
		for _, in := range ingresses {
			reason := "Ingress " + firstOr(in.hosts(), in.Metadata.Name)
			for _, svc := range in.backends() {
				exposed[in.Metadata.Namespace+"/"+svc] = reason
			}
		}
	}
	for _, kind := range []string{"httproutes", "grpcroutes"} {
		routes, err := kube.List[route](ctx, c, "/apis/gateway.networking.k8s.io/v1/"+kind, "", 500)
		if !optional(kind, err) {
			continue
		}
		for _, r := range routes {
			reason := kindName(kind) + " " + firstOr(r.Spec.Hostnames, r.Metadata.Name)
			for _, rule := range r.Spec.Rules {
				for _, b := range rule.BackendRefs {
					if (b.Kind != "" && b.Kind != "Service") || (b.Group != "" && b.Group != "core") {
						continue
					}
					ns := r.Metadata.Namespace
					if b.Namespace != "" {
						ns = b.Namespace
					}
					exposed[ns+"/"+b.Name] = reason
				}
			}
		}
	}
	inv.Workloads = workloads(pods, cronJobs, services, exposed)

	apps, err := kube.List[application](ctx, c, "/apis/argoproj.io/v1alpha1/applications", "", 200)
	if optional("argo cd applications", err) {
		for _, a := range apps {
			inv.Apps = append(inv.Apps, a.charts()...)
		}
	}

	// Release secrets carry the whole chart; small pages keep responses small.
	secrets, err := kube.List[secret](ctx, c, "/api/v1/secrets", "owner=helm,status=deployed", 10)
	if optional("helm releases", err) {
		latest := map[string]*helmRelease{}
		for _, s := range secrets {
			r, err := decodeRelease(s.Data["release"])
			if err != nil {
				inv.Warnings = append(inv.Warnings, fmt.Sprintf("helm release %s/%s: %v", s.Metadata.Namespace, s.Metadata.Name, err))
				continue
			}
			key := r.Namespace + "/" + r.Name
			if prev := latest[key]; prev == nil || r.Version > prev.Version {
				latest[key] = r
			}
		}
		for _, key := range slices.Sorted(maps.Keys(latest)) {
			r := latest[key]
			inv.Releases = append(inv.Releases, Release{Name: r.Name, Namespace: r.Namespace, Chart: r.chart()})
		}
	}
	return inv, nil
}

func kindName(plural string) string {
	switch plural {
	case "httproutes":
		return "HTTPRoute"
	case "grpcroutes":
		return "GRPCRoute"
	}
	return plural
}

func firstOr(list []string, def string) string {
	if len(list) > 0 && list[0] != "" {
		return list[0]
	}
	return def
}

type meta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	Labels          map[string]string `json:"labels"`
	OwnerReferences []struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"ownerReferences"`
}

type node struct {
	Metadata meta `json:"metadata"`
	Status   struct {
		NodeInfo struct {
			KubeletVersion          string `json:"kubeletVersion"`
			ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
			OSImage                 string `json:"osImage"`
			KernelVersion           string `json:"kernelVersion"`
		} `json:"nodeInfo"`
	} `json:"status"`
}

type podSpec struct {
	Containers     []struct{ Image string } `json:"containers"`
	InitContainers []struct{ Image string } `json:"initContainers"`
}

func (s podSpec) images() []string {
	var out []string
	for _, c := range append(s.InitContainers, s.Containers...) {
		if c.Image != "" && !slices.Contains(out, c.Image) {
			out = append(out, c.Image)
		}
	}
	return out
}

type pod struct {
	Metadata meta    `json:"metadata"`
	Spec     podSpec `json:"spec"`
	Status   struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

type cronJob struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		JobTemplate struct {
			Spec struct {
				Template struct {
					Spec podSpec `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
		} `json:"jobTemplate"`
	} `json:"spec"`
}

type service struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Type     string            `json:"type"`
		Selector map[string]string `json:"selector"`
	} `json:"spec"`
}

type ingressBackend struct {
	Service *struct {
		Name string `json:"name"`
	} `json:"service"`
}

type ingress struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		DefaultBackend *ingressBackend `json:"defaultBackend"`
		Rules          []struct {
			Host string `json:"host"`
			HTTP *struct {
				Paths []struct {
					Backend ingressBackend `json:"backend"`
				} `json:"paths"`
			} `json:"http"`
		} `json:"rules"`
	} `json:"spec"`
}

func (in ingress) hosts() []string {
	var out []string
	for _, r := range in.Spec.Rules {
		if r.Host != "" {
			out = append(out, r.Host)
		}
	}
	return out
}

func (in ingress) backends() []string {
	var out []string
	if b := in.Spec.DefaultBackend; b != nil && b.Service != nil {
		out = append(out, b.Service.Name)
	}
	for _, r := range in.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		for _, p := range r.HTTP.Paths {
			if p.Backend.Service != nil {
				out = append(out, p.Backend.Service.Name)
			}
		}
	}
	return out
}

type route struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Hostnames []string `json:"hostnames"`
		Rules     []struct {
			BackendRefs []struct {
				Group     string `json:"group"`
				Kind      string `json:"kind"`
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"backendRefs"`
		} `json:"rules"`
	} `json:"spec"`
}

type appSource struct {
	RepoURL        string `json:"repoURL"`
	Chart          string `json:"chart"`
	TargetRevision string `json:"targetRevision"`
	Helm           *struct {
		ReleaseName string `json:"releaseName"`
	} `json:"helm"`
}

type application struct {
	Metadata meta `json:"metadata"`
	Spec     struct {
		Source      *appSource  `json:"source"`
		Sources     []appSource `json:"sources"`
		Destination struct {
			Server    string `json:"server"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"destination"`
	} `json:"spec"`
}

// charts returns the Helm chart sources of the Application.
func (a application) charts() []App {
	srcs := a.Spec.Sources
	if a.Spec.Source != nil {
		srcs = append(srcs, *a.Spec.Source)
	}
	d := a.Spec.Destination
	inCluster := d.Server == "https://kubernetes.default.svc" || d.Name == "in-cluster" || (d.Server == "" && d.Name == "")
	var out []App
	for _, s := range srcs {
		if s.Chart == "" {
			continue
		}
		repo := s.RepoURL
		if !strings.Contains(repo, "://") {
			repo = "oci://" + strings.TrimSuffix(repo, "/") // Argo CD writes OCI Helm repositories without a scheme
		}
		release := a.Metadata.Name
		if s.Helm != nil && s.Helm.ReleaseName != "" {
			release = s.Helm.ReleaseName
		}
		out = append(out, App{
			Name: a.Metadata.Name, Namespace: d.Namespace, Repo: repo, Chart: s.Chart,
			Version: s.TargetRevision, ReleaseName: release, External: !inCluster,
		})
	}
	return out
}

type secret struct {
	Metadata meta              `json:"metadata"`
	Data     map[string][]byte `json:"data"`
}

// workloads groups the running pods (and CronJob templates, whose pods are
// usually gone) by owner and image, and marks those behind an exposed
// Service.
func workloads(pods []pod, cronJobs []cronJob, services []service, exposed map[string]string) []Workload {
	type key struct{ ns, owner, image string }
	acc := map[key]*Workload{}
	var order []key
	add := func(ns, owner, image, exp string, pods int) {
		k := key{ns, owner, image}
		w := acc[k]
		if w == nil {
			w = &Workload{Namespace: ns, Owner: owner, Image: imageref.Parse(image)}
			acc[k] = w
			order = append(order, k)
		}
		w.Pods += pods
		if w.Exposed == "" {
			w.Exposed = exp
		}
	}
	for _, p := range pods {
		if p.Status.Phase == "Succeeded" || p.Status.Phase == "Failed" {
			continue
		}
		exp := ""
		for _, s := range services {
			reason := exposed[s.Metadata.Namespace+"/"+s.Metadata.Name]
			if reason != "" && s.Metadata.Namespace == p.Metadata.Namespace && selects(s.Spec.Selector, p.Metadata.Labels) {
				exp = reason
				break
			}
		}
		for _, img := range p.Spec.images() {
			add(p.Metadata.Namespace, owner(p.Metadata), img, exp, 1)
		}
	}
	for _, cj := range cronJobs {
		for _, img := range cj.Spec.JobTemplate.Spec.Template.Spec.images() {
			add(cj.Metadata.Namespace, "CronJob/"+cj.Metadata.Name, img, "", 0)
		}
	}
	out := make([]Workload, 0, len(order))
	for _, k := range order {
		out = append(out, *acc[k])
	}
	return out
}

func selects(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// owner names the controller of a pod; a ReplicaSet's or Job's generated
// suffix is dropped to name the Deployment or CronJob.
func owner(m meta) string {
	if len(m.OwnerReferences) == 0 {
		return "Pod/" + m.Name
	}
	o := m.OwnerReferences[0]
	switch o.Kind {
	case "ReplicaSet":
		if i := strings.LastIndex(o.Name, "-"); i > 0 {
			return "Deployment/" + o.Name[:i]
		}
	case "Job":
		if i := strings.LastIndex(o.Name, "-"); i > 0 && strings.Trim(o.Name[i+1:], "0123456789") == "" {
			return "CronJob/" + o.Name[:i]
		}
	}
	return o.Kind + "/" + o.Name
}
