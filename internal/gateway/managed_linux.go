//go:build linux

package gateway

import (
	"errors"
	"net"

	"github.com/123123213weqw/Xandbox/internal/policycontrol"
)

var errManagedConflict = errors.New("managed gateway activation conflict")

type policyObservation interface {
	Status() policycontrol.PolicyStatus
	Publish(policycontrol.PolicyStatus) error
}

func fenceManaged(view policyObservation) {
	s := view.Status()
	s.Phase = "fenced"
	_ = view.Publish(s)
}

// The supervisor's single writer calls this after complete snapshot/binding
// validation. A duplicate never recommits, seals or transfers a policy. Real
// durable completion and real child ACK are deliberately separate transitions.
func commitManaged(state *policyState, parent *net.UnixConn, s Snapshot, command policycontrol.PolicyCommand, view policyObservation) (err error) {
	duplicate, e := policycontrol.Classify(command, view.Status())
	if e != nil {
		return errManagedConflict
	}
	if duplicate {
		return nil
	}
	digest, e := SnapshotDigest(s)
	if e != nil || s.Epoch != command.TargetEpoch || digest != command.SnapshotSHA256 {
		return errManagedConflict
	}
	fd, e := sealedSnapshot(s)
	if e != nil {
		return errors.New("cannot seal managed gateway policy")
	}
	defer fd.Close()
	progress := view.Status()
	progress.Phase = "committing"
	if e = view.Publish(progress); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			fenceManaged(view)
		}
	}()
	if e = state.Commit(s); e != nil {
		return errors.New("managed gateway durable commit failed")
	}
	progress.DurableEpoch = s.Epoch
	progress.SnapshotSHA256 = digest
	progress.Phase = "waiting"
	if e = view.Publish(progress); e != nil {
		return e
	}
	if e = writeFrame(parent, frame{op: opPolicy, request: s.Epoch}, int(fd.Fd())); e != nil {
		return errors.New("managed gateway policy transfer failed")
	}
	return nil
}

func acknowledgeManaged(view policyObservation, epoch uint64) error {
	s := view.Status()
	if s.Phase != "waiting" || epoch != s.DurableEpoch {
		return errors.New("invalid managed gateway acknowledgement")
	}
	s.ActiveEpoch = s.DurableEpoch
	s.ActiveSHA256 = s.SnapshotSHA256
	s.Phase = "active"
	return view.Publish(s)
}
