// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"

	"github.com/omec-project/li/types"
)

// TestActivateDoesNotShareTheCallersArrays: the read path clones because a caller
// holding the store's backing arrays can mutate them outside the lock, which is a
// data race and — since the arrays are a warrant's targets — cross-warrant
// corruption. Storing the caller's arrays is the same hazard entered from the
// other side, and the store cannot see which of its callers keeps a reference.
func TestActivateDoesNotShareTheCallersArrays(t *testing.T) {
	targets := []types.TargetIdentifier{{Type: types.TargetSUPI, Value: "262019876543210"}}
	dids := []string{"7d1c2f60-8a4e-4a1e-9f3b-2c5d6e7f8091"}

	s := New()
	if !s.Activate(types.InterceptTask{
		XID:      "warrant-1",
		Targets:  targets,
		DIDs:     dids,
		Products: []types.ProductType{types.ProductIRI},
		State:    types.TaskActive,
	}) {
		t.Fatal("Activate failed")
	}

	// The caller reuses its own slices, as any caller is entitled to.
	targets[0] = types.TargetIdentifier{Type: types.TargetSUPI, Value: "999999999999999"}
	dids[0] = "not-the-did-that-was-provisioned"

	held, ok := s.Get("warrant-1")
	if !ok {
		t.Fatal("the task is gone")
	}
	if got := held.Targets[0].Value; got != "262019876543210" {
		t.Errorf("stored target = %q, want the value provisioned — the store shares its "+
			"backing array with the caller, so a warrant now names a subject nobody "+
			"authorised intercepting", got)
	}
	if got := held.DIDs[0]; got != "7d1c2f60-8a4e-4a1e-9f3b-2c5d6e7f8091" {
		t.Errorf("stored dId = %q, want the value provisioned", got)
	}

	// And the index has to agree with the record, or Match and Get answer differently.
	if n := len(s.Match(types.TargetIdentifier{Type: types.TargetSUPI, Value: "262019876543210"})); n != 1 {
		t.Errorf("Match found %d tasks for the provisioned subject, want 1", n)
	}
}
