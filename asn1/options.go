// SPDX-FileCopyrightText: 2016 PromonLogicalis
// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: MIT

package asn1

import (
	"reflect"
	"strconv"
	"strings"
)

type fieldOptions struct {
	universal    bool
	application  bool
	explicit     bool
	indefinite   bool
	optional     bool
	set          bool
	tag          *int
	defaultValue *int
	choice       *string

	// LOCAL PATCH (omec/li) 7/8: elemChoice carries a CHOICE that applies to the
	// *elements* of a SEQUENCE OF / SET OF rather than to the field itself. It is
	// never written in a struct tag — splitElementChoice derives it from `choice`
	// when the field's declared type is a non-byte slice or array. See the
	// SEQUENCE OF CHOICE entry in README.md.
	elemChoice *string
}

// splitElementChoice moves a `choice` written on a SEQUENCE OF / SET OF field down
// to its elements, so the CHOICE is resolved per element instead of against the
// slice type (which has no registered alternative and previously failed with
// "invalid Go type '[]interface {}' for choice ...").
//
// LOCAL PATCH (omec/li) 7/8.
//
// declared must be the field's *declared* type, read before any interface unwrap.
// That is what separates the two readings of a choice option on one field:
//
//   - a field declared []any, tagged choice:c — the CHOICE applies to each
//     element, which is SEQUENCE OF CHOICE.
//   - a field declared any, tagged choice:c, holding a slice value — the CHOICE
//     applies to the whole value, and one registered alternative simply happens
//     to be a slice type.
//
// A byte slice or byte array is left alone: it is an OCTET STRING, not a
// SEQUENCE OF, and may itself be a CHOICE alternative (e.g. an IPv4Address).
func splitElementChoice(declared reflect.Type, opts *fieldOptions) *fieldOptions {
	if opts.choice == nil || declared == nil {
		return opts
	}
	switch declared.Kind() {
	case reflect.Slice, reflect.Array:
		if declared.Elem().Kind() == reflect.Uint8 {
			return opts
		}
	default:
		return opts
	}
	derived := *opts
	derived.elemChoice = opts.choice
	derived.choice = nil
	return &derived
}

// elementOptions returns the options to apply to each element of a SEQUENCE OF /
// SET OF whose elements are a CHOICE. Only the choice travels: the field's tag,
// optionality and explicitness belong to the sequence, not to its members.
//
// LOCAL PATCH (omec/li) 7/8.
func elementOptions(opts *fieldOptions) *fieldOptions {
	return &fieldOptions{choice: opts.elemChoice}
}

// validate returns an error if any option is invalid.
func (opts *fieldOptions) validate() error {
	tagError := func(class string) error {
		return syntaxError(
			"'tag' must be specified when '%s' is used", class)
	}
	if opts.universal && opts.tag == nil {
		return tagError("universal")
	}
	if opts.application && opts.tag == nil {
		return tagError("application")
	}
	if opts.tag != nil && *opts.tag < 0 {
		return syntaxError("'tag' cannot be negative: %d", *opts.tag)
	}
	if opts.choice != nil && *opts.choice == "" {
		return syntaxError("'choice' cannot be empty")
	}
	return nil
}

// parseOption returns a parsed fieldOptions or an error.
func parseOptions(s string) (*fieldOptions, error) {
	var opts fieldOptions
	for _, token := range strings.Split(s, ",") {
		args := strings.Split(strings.TrimSpace(token), ":")
		err := parseOption(&opts, args)
		if err != nil {
			return nil, err
		}
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	return &opts, nil
}

// parseOption parse a single option.
func parseOption(opts *fieldOptions, args []string) error {
	var err error
	switch args[0] {
	case "":
		// ignore

	case "universal":
		opts.universal, err = parseBoolOption(args)

	case "application":
		opts.application, err = parseBoolOption(args)

	case "explicit":
		opts.explicit, err = parseBoolOption(args)

	case "indefinite":
		opts.indefinite, err = parseBoolOption(args)

	case "optional":
		opts.optional, err = parseBoolOption(args)

	case "set":
		opts.set, err = parseBoolOption(args)

	case "tag":
		opts.tag, err = parseIntOption(args)

	case "default":
		opts.defaultValue, err = parseIntOption(args)

	case "choice":
		opts.choice, err = parseStringOption(args)

	default:
		err = syntaxError("Invalid option: %s", args[0])
	}
	return err
}

// parseBoolOption just checks if no arguments were given.
func parseBoolOption(args []string) (bool, error) {
	if len(args) > 1 {
		return false, syntaxError("option '%s' does not have arguments.",
			args[0])
	}
	return true, nil
}

// parseIntOption parses an integer argument.
func parseIntOption(args []string) (*int, error) {
	if len(args) != 2 {
		return nil, syntaxError("option '%s' does not have arguments.", args[0])
	}
	num, err := strconv.Atoi(args[1])
	if err != nil {
		return nil, syntaxError("invalid value '%s' for option '%s'.",
			args[1], args[0])
	}
	return &num, nil
}

// parseStringOption parses a string argument.
func parseStringOption(args []string) (*string, error) {
	if len(args) != 2 {
		return nil, syntaxError("option '%s' does not have arguments.", args[0])
	}
	return &args[1], nil
}
