// Package hostdoctor observes necessary host prerequisites without installing
// services, changing cgroups or opening KVM. It does not certify readiness.
package hostdoctor

import "context"

const RequiredSystemdMajor = 254

type Check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Code   string `json:"code"`
}

type Report struct {
	Version               int      `json:"version"`
	Profile               string   `json:"profile"`
	OS                    string   `json:"os"`
	Architecture          string   `json:"architecture"`
	RequiredSystemdMajor  int      `json:"required_systemd_major"`
	ObservedSystemdMajor  int      `json:"observed_systemd_major"`
	BasicPrerequisitesMet bool     `json:"basic_prerequisites_met"`
	Checks                []Check  `json:"checks"`
	MissingControllers    []string `json:"missing_controllers"`
	DeferredChecks        []string `json:"deferred_checks"`
	ReadOnly              bool     `json:"read_only"`
	VMCreated             bool     `json:"vm_created"`
	IsolationValidated    bool     `json:"isolation_validated"`
	ProductionReady       bool     `json:"production_ready"`
}

type state int

const (
	unobserved state = iota
	available
	unavailable
	denied
	malformed
)

type observation struct {
	os, arch                                        string
	pid1, manager, cgroup, controllers, kvm, access state
	major                                           int
	missing                                         []string
}

// Collect returns a closed, path/error/credential-free report. Filesystem
// observations are not an atomic host snapshot or a deployment authorization.
func Collect(ctx context.Context) Report { return summarize(observe(ctx)) }

func summarize(o observation) Report {
	r := Report{Version: 1, Profile: "systemd-install-v1", OS: "other", Architecture: "other",
		RequiredSystemdMajor: RequiredSystemdMajor, BasicPrerequisitesMet: true, ReadOnly: true,
		MissingControllers: []string{}, Checks: []Check{}, DeferredChecks: []string{
			"actual_kvm_creation", "clone3_and_namespace_capabilities", "unit_delegation_and_budget_readback",
			"asset_hashes_and_guest_health", "storage_quota_and_backing_device", "reserved_uids_and_trusted_paths",
			"node_capacity_and_pressure", "network_and_tls_policy", "production_fault_matrix_and_slos",
		}}
	for _, name := range []string{"linux", "darwin", "windows"} {
		if o.os == name {
			r.OS = name
		}
	}
	for _, name := range []string{"amd64", "arm64"} {
		if o.arch == name {
			r.Architecture = name
		}
	}
	add := func(id, status, code string) {
		r.Checks = append(r.Checks, Check{id, status, code})
		if status != "pass" {
			r.BasicPrerequisitesMet = false
		}
	}
	if o.os == "linux" {
		add("linux", "pass", "linux_observed")
	} else {
		add("linux", "fail", "linux_required")
	}
	if o.arch == "amd64" {
		add("architecture", "pass", "qualified_fixture_architecture")
	} else {
		add("architecture", "unknown", "architecture_requires_separate_qualification")
	}
	if o.pid1 == available {
		add("systemd_pid1", "pass", "systemd_pid1_observed")
	} else if o.pid1 == unavailable {
		add("systemd_pid1", "fail", "systemd_pid1_required")
	} else {
		add("systemd_pid1", "unknown", "pid1_observation_unavailable")
	}
	if o.pid1 == available && o.manager == available && o.major > 0 && o.major <= 9999 {
		r.ObservedSystemdMajor = o.major
		if o.major >= RequiredSystemdMajor {
			add("systemd_version", "pass", "running_manager_version_floor_met")
		} else {
			add("systemd_version", "fail", "dedicated_newer_systemd_node_required")
		}
	} else {
		add("systemd_version", "unknown", "running_manager_version_unconfirmed")
	}
	if o.cgroup == available {
		add("cgroup_v2", "pass", "cgroup2_filesystem_observed")
	} else if o.cgroup == unavailable {
		add("cgroup_v2", "fail", "unified_cgroup2_required")
	} else {
		add("cgroup_v2", "unknown", "cgroup_filesystem_unconfirmed")
	}
	if o.cgroup == available && o.controllers == available && len(o.missing) == 0 {
		add("controllers", "pass", "root_controllers_observed_not_unit_delegation")
	} else if o.cgroup == available && o.controllers == unavailable && len(o.missing) > 0 {
		add("controllers", "fail", "required_root_controller_missing")
	} else {
		add("controllers", "unknown", "controller_inventory_unconfirmed")
	}
	// Only these four public names can be projected, in a fixed order.
	for _, name := range []string{"cpu", "io", "memory", "pids"} {
		for _, missing := range o.missing {
			if missing == name {
				r.MissingControllers = append(r.MissingControllers, name)
				break
			}
		}
	}
	if o.kvm == available {
		add("kvm_device", "pass", "kvm_character_device_observed_not_opened")
	} else if o.kvm == unavailable {
		add("kvm_device", "fail", "kvm_character_device_required")
	} else {
		add("kvm_device", "unknown", "kvm_device_unconfirmed")
	}
	if o.kvm == available && o.access == available {
		add("kvm_permissions", "pass", "caller_access_observed_not_device_open")
	} else if o.kvm == available && o.access == denied {
		add("kvm_permissions", "fail", "authorized_operator_access_required")
	} else {
		add("kvm_permissions", "unknown", "caller_device_access_unconfirmed")
	}
	return r
}
