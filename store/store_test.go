// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"testing"

	"github.com/omec-project/li/types"
)

func supi(v string) types.TargetIdentifier {
	return types.TargetIdentifier{Type: types.TargetSUPI, Value: v}
}

func TestActivateMatchDeactivate(t *testing.T) {
	s := New()
	target := supi("imsi-001010000000001")
	task := types.InterceptTask{
		XID:      "W1",
		Target:   target,
		Products: []types.ProductType{types.ProductIRI, types.ProductCC},
	}

	if !s.Activate(task) {
		t.Fatal("Activate returned false for a valid task")
	}

	got := s.Match(target)
	if len(got) != 1 || got[0].XID != "W1" {
		t.Fatalf("Match(target) = %+v, want one task W1", got)
	}
	if got[0].State != types.TaskActive {
		t.Errorf("task state = %q, want %q", got[0].State, types.TaskActive)
	}
	if !got[0].WantsProduct(types.ProductCC) {
		t.Errorf("task should want CC product")
	}

	if m := s.Match(supi("other")); m != nil {
		t.Errorf("Match of non-target returned %+v, want nil", m)
	}

	if !s.Deactivate("W1") {
		t.Fatal("Deactivate returned false for an active task")
	}
	if m := s.Match(target); m != nil {
		t.Errorf("Match after Deactivate returned %+v, want nil", m)
	}
	if s.Len() != 0 {
		t.Errorf("Len after Deactivate = %d, want 0", s.Len())
	}
}

func TestActivateRejectsEmptyXID(t *testing.T) {
	s := New()
	if s.Activate(types.InterceptTask{Target: supi("x")}) {
		t.Error("Activate accepted a task with an empty XID")
	}
	if s.Len() != 0 {
		t.Errorf("Len = %d, want 0", s.Len())
	}
}

func TestModifyTaskRetargets(t *testing.T) {
	s := New()
	oldT, newT := supi("old"), supi("new")
	s.Activate(types.InterceptTask{XID: "W1", Target: oldT})

	// X1 ModifyTask: same XID, different target.
	s.Activate(types.InterceptTask{XID: "W1", Target: newT})

	if m := s.Match(oldT); m != nil {
		t.Errorf("old target still matches after retarget: %+v", m)
	}
	if m := s.Match(newT); len(m) != 1 {
		t.Errorf("new target Match = %+v, want one task", m)
	}
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1 (modify must not duplicate)", s.Len())
	}
}

func TestDeactivateUnknownXID(t *testing.T) {
	s := New()
	if s.Deactivate("nope") {
		t.Error("Deactivate of unknown XID returned true")
	}
}
