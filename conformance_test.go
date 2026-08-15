// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: Apache-2.0

// Package li holds no code. It exists so that the conformance index at the module
// root can be checked by a test rather than by a convention.
package li

import (
	"os"
	"strings"
	"testing"
)

// dispositions are the per-interface conformance documents. Every interface for
// which this project claims conformance has one, and the public compliance claim
// links to the index that names them — so a disposition added, renamed or moved
// without the index following orphans that link silently.
//
// This is the same reflex the schema-drift check applies to the X1 structs, aimed
// at documentation structure instead: the failure mode being guarded is not that
// somebody writes the wrong thing, it is that somebody moves a file and nothing
// says so.
var dispositions = []string{
	"x1/CONFORMANCE.md",
	"x2x3/CONFORMANCE.md",
	"iri/CONFORMANCE.md",
}

const index = "CONFORMANCE.md"

func TestEveryDispositionExistsAndIsIndexed(t *testing.T) {
	body, err := os.ReadFile(index)
	if err != nil {
		t.Fatalf("reading %s: %v — the public compliance claim links here", index, err)
	}
	text := string(body)

	for _, path := range dispositions {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s: %v — an interface this project claims conformance for has no disposition distributed with the code", path, err)

			continue
		}
		if !strings.Contains(text, path) {
			t.Errorf("%s exists but %s does not reference it; a reader arriving from the compliance page cannot reach it", path, index)
		}
	}
}

// TestTheIndexReferencesNothingMissing is the other direction, and the one that
// catches a rename: the index naming a document that is not there is a broken link
// on the page a prospective operator is sent to.
func TestTheIndexReferencesNothingMissing(t *testing.T) {
	body, err := os.ReadFile(index)
	if err != nil {
		t.Fatalf("reading %s: %v", index, err)
	}

	for _, field := range strings.Fields(strings.NewReplacer("(", " ", ")", " ", "`", " ", "[", " ", "]", " ").Replace(string(body))) {
		if !strings.HasSuffix(field, "CONFORMANCE.md") || field == index {
			continue
		}
		if _, err := os.Stat(field); err != nil {
			t.Errorf("%s names %q, which is not there: %v", index, field, err)
		}
	}
}
