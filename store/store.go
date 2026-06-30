// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package store maintains the set of active Lawful Interception tasks for a
// network function, indexed by target identifier. It lets the NF match events
// and traffic against tasked targets locally, with no external lookup at
// interception time (per the li-provisioning capability).
package store

import (
	"sync"

	"github.com/omec-project/li/types"
)

// Store is a concurrency-safe set of active interception tasks. The zero value
// is not usable; construct with New.
type Store struct {
	mu       sync.RWMutex
	byXID    map[types.XID]types.InterceptTask
	byTarget map[types.TargetIdentifier]map[types.XID]struct{}
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		byXID:    make(map[types.XID]types.InterceptTask),
		byTarget: make(map[types.TargetIdentifier]map[types.XID]struct{}),
	}
}

// Activate adds or replaces a task (X1 ActivateTask / ModifyTask). It re-indexes
// by target so a ModifyTask that changes the target identifier is handled
// correctly. A task with an empty XID is rejected and reported false.
func (s *Store) Activate(task types.InterceptTask) bool {
	if task.XID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unindex(task.XID) // drop any prior indexing for this XID
	task.State = types.TaskActive
	s.byXID[task.XID] = task
	set := s.byTarget[task.Target]
	if set == nil {
		set = make(map[types.XID]struct{})
		s.byTarget[task.Target] = set
	}
	set[task.XID] = struct{}{}
	return true
}

// Deactivate removes a task (X1 DeactivateTask). After this the task produces no
// further intercept product. Reports whether the task existed.
func (s *Store) Deactivate(xid types.XID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byXID[xid]; !ok {
		return false
	}
	s.unindex(xid)
	delete(s.byXID, xid)
	return true
}

// unindex removes the target-index entry for xid using its currently stored
// task. The caller must hold the write lock.
func (s *Store) unindex(xid types.XID) {
	prev, ok := s.byXID[xid]
	if !ok {
		return
	}
	if set := s.byTarget[prev.Target]; set != nil {
		delete(set, xid)
		if len(set) == 0 {
			delete(s.byTarget, prev.Target)
		}
	}
}

// Get returns the active task for an XID.
func (s *Store) Get(xid types.XID) (types.InterceptTask, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.byXID[xid]
	return t, ok
}

// Match returns the active tasks targeting the given identifier. The result is a
// fresh slice the caller may use without holding any lock; nil if no task matches.
func (s *Store) Match(id types.TargetIdentifier) []types.InterceptTask {
	s.mu.RLock()
	defer s.mu.RUnlock()
	set := s.byTarget[id]
	if len(set) == 0 {
		return nil
	}
	out := make([]types.InterceptTask, 0, len(set))
	for xid := range set {
		out = append(out, s.byXID[xid])
	}
	return out
}

// Len returns the number of active tasks.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byXID)
}
