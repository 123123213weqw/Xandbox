package installtxn

import (
	"github.com/123123213weqw/Xandbox/internal/firecracker"
	"github.com/123123213weqw/Xandbox/internal/launch"
	"github.com/123123213weqw/Xandbox/internal/policycontrol"
	"github.com/123123213weqw/Xandbox/internal/serviceready"
	"strings"
)

// Fixed original generators and envelopes. Results comes ONLY from the fresh
// pinned Config4 in the actual producer/verifier; it is not a second policy.
func renderResults(p Plan, device string, art map[string]Artifact, results firecracker.ResultPolicy) (map[string][]byte, error) {
	if p.Version != 2 || !results.Valid() {
		return nil, ErrPolicy
	}
	n := nodeManifest(p, art)
	// Produce the private V2 contract's exact JSON+LF for its pin and output.
	// All generator/composition checks below still run; no IO or callback sees
	// these bytes before the final artifact map is returned. Not a source cache.
	contract, e := launch.NewResultContract(n, results)
	if e != nil {
		return nil, ErrPolicy
	}
	nodeLine, e := contract.Line()
	if e != nil {
		return nil, ErrPolicy
	}
	g := ingressManifestWithNodeSHA(p, digest(nodeLine), device, art)
	r := serviceready.Manifest{Version: 1, NodeLaunch: g.NodeLaunch, Helper: firecracker.Asset{Path: serviceready.HelperPath, SHA256: art["ready"].SHA256}, Device: device}
	main, e := r.DaemonUnit(n, readyPath, p.DevicePath)
	if e != nil {
		return nil, ErrPolicy
	}
	ingress, e := g.Unit(n, ingressPath, p.DevicePath)
	if e != nil {
		return nil, ErrPolicy
	}
	needle := "Type=exec\nExecStart="
	if strings.Count(main, needle) != 1 {
		return nil, ErrPolicy
	}
	main = strings.Replace(main, needle, "Type=exec\nExecStartPre="+SelfPath+" verify-results\nExecStart=", 1)
	if p.Version == 2 {
		line := "ReadWritePaths=" + policyDir + "\n"
		if strings.Count(ingress, line) != 1 || strings.Count(ingress, "Type=exec\n") != 1 {
			return nil, ErrPolicy
		}
		ingress = strings.Replace(ingress, line, "ReadWritePaths="+policyDir+" "+policycontrol.OperatorDirectory+"\n", 1)
		ingress = strings.Replace(ingress, "Type=exec\n", "Type=exec\nRuntimeDirectory=xandbox-ingress-control\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=no\n", 1)
	}
	return map[string][]byte{launchPath: nodeLine, ingressPath: encode(g), readyPath: encode(r), UnitDir + "/" + MainUnit: []byte(main), UnitDir + "/" + IngressUnit: []byte(ingress)}, nil
}
