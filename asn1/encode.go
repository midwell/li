// SPDX-FileCopyrightText: 2016 PromonLogicalis
// SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
// SPDX-License-Identifier: MIT

package asn1

import (
	"reflect"
	"sort"
	"unicode"
)

// Encode returns the ASN.1 encoding of obj.
//
// See (*Context).EncodeWithOptions() for further details.
func (ctx *Context) Encode(obj interface{}) (data []byte, err error) {
	return ctx.EncodeWithOptions(obj, "")
}

// EncodeWithOptions returns the ASN.1 encoding of obj using additional options.
//
// See (*Context).DecodeWithOptions() for further details regarding types and
// options.
func (ctx *Context) EncodeWithOptions(obj interface{}, options string) (data []byte, err error) {
	opts, err := parseOptions(options)
	if err != nil {
		return nil, err
	}

	value := reflect.ValueOf(obj)
	raw, err := ctx.encode(value, opts)
	if err != nil {
		return
	}
	data, err = raw.encode()
	return
}

// Main encode function
func (ctx *Context) encode(value reflect.Value, opts *fieldOptions) (*rawValue, error) {
	// LOCAL PATCH (omec/li) 7/8: a `choice` on a SEQUENCE OF / SET OF field applies
	// to its elements. Split it before the interface unwrap below, which is the only
	// point where the field's declared type is still visible.
	if value.IsValid() {
		opts = splitElementChoice(value.Type(), opts)
	}

	// Skip the interface type
	switch value.Kind() {
	case reflect.Interface:
		value = value.Elem()
	}

	// LOCAL PATCH (omec/li): a nil interface unwraps to an invalid reflect.Value.
	// Upstream then panics in isEmpty/encodeValue (reflect.Value.Type on a zero
	// Value). Treat an absent optional/default field as omitted; a missing
	// mandatory field becomes a clear error instead of a panic. This mirrors how
	// the aper codec treats a nil pointer as an absent OPTIONAL field.
	if !value.IsValid() {
		if opts.optional || opts.defaultValue != nil {
			return nil, nil
		}
		return nil, syntaxError("missing value for mandatory field")
	}

	// LOCAL PATCH (omec/li): pointer support, which is how an OPTIONAL field says
	// "present, and equal to my type's zero value".
	//
	// isEmpty below cannot draw that distinction: it compares against the zero value,
	// so an OPTIONAL BOOLEAN can encode true and can never encode false. TS 33.128's
	// sUPIUnauthenticated is exactly that field, and false -- the SUPI *was*
	// authenticated -- is its ordinary value. Marking it mandatory instead would emit
	// an authentication status in records carrying no SUPI, asserting something about
	// an identity that is not there.
	//
	// A nil pointer is absent. A non-nil pointer is present and encodes its pointee
	// even when the pointee is zero. Nothing else changes: this branch is reachable
	// only from a field declared as a pointer, and a field that is not one takes
	// exactly the path it did before. That is what makes the fix opt-in, and what lets
	// the golden vectors show it inert rather than merely assert it.
	//
	// One pointer type is excluded: *big.Int, which encodeValue already handles as a
	// special type below. Dereferencing it here would strip the very type that
	// dispatch keys on, and an INTEGER would silently encode as an empty SEQUENCE.
	// The existing suite catches it, which is why this exclusion is a line of code
	// and not a paragraph of hindsight.
	pointerPresent := false
	if value.Kind() == reflect.Ptr && value.Type() != bigIntType {
		if value.IsNil() {
			if opts.optional || opts.defaultValue != nil {
				return nil, nil
			}
			return nil, syntaxError("missing value for mandatory field")
		}
		value = value.Elem()
		pointerPresent = true
	}

	// If a value is missing the default value is used
	empty := isEmpty(value)
	// An explicitly-set pointer is never empty, so it is neither omitted below nor
	// replaced by a DEFAULT: the author said which value they meant.
	if pointerPresent {
		empty = false
	}
	if opts.defaultValue != nil {
		if empty && !ctx.der.encoding {
			defaultValue, err := ctx.newDefaultValue(value.Type(), opts)
			if err != nil {
				return nil, err
			}
			value = defaultValue
			empty = false
		}
	}

	// Encode data
	raw, err := ctx.encodeValue(value, opts)
	if err != nil {
		return nil, err
	}

	// Since the empty flag is already calculated, check if it's optional
	if (opts.optional || opts.defaultValue != nil) && empty {
		return nil, nil
	}

	// Modify the data generated based on the given tags
	raw, err = ctx.applyOptions(value, raw, opts)
	if err != nil {
		return nil, err
	}

	return raw, nil
}

func (ctx *Context) encodeValue(value reflect.Value, opts *fieldOptions) (raw *rawValue, err error) {
	raw = &rawValue{}
	encoder := encoderFunction(nil)

	// Special types:
	objType := value.Type()
	switch objType {
	case bigIntType:
		raw.Tag = tagInteger
		encoder = ctx.encodeBigInt
	case oidType:
		raw.Tag = tagOid
		encoder = ctx.encodeOid
	case nullType:
		raw.Tag = tagNull
		encoder = ctx.encodeNull
	}

	if encoder == nil {
		// Generic types:
		switch value.Kind() {
		case reflect.Bool:
			raw.Tag = tagBoolean
			encoder = ctx.encodeBool

		case reflect.String:
			raw.Tag = tagOctetString
			encoder = ctx.encodeString

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			raw.Tag = tagInteger
			encoder = ctx.encodeInt

		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			raw.Tag = tagInteger
			encoder = ctx.encodeUint

		case reflect.Struct:
			raw.Tag = tagSequence
			raw.Constructed = true
			encoder = ctx.encodeStruct
			if opts.set {
				encoder = ctx.encodeStructAsSet
			}

		case reflect.Array, reflect.Slice:
			if objType.Elem().Kind() == reflect.Uint8 {
				raw.Tag = tagOctetString
				encoder = ctx.encodeOctetString
			} else {
				raw.Tag = tagSequence
				raw.Constructed = true
				encoder = ctx.encodeSlice
				// LOCAL PATCH (omec/li) 7/8: SEQUENCE OF CHOICE — each element is
				// encoded with the CHOICE the field declared.
				if opts.elemChoice != nil {
					elemOpts := elementOptions(opts)
					encoder = func(v reflect.Value) ([]byte, error) {
						return ctx.encodeSliceWithOptions(v, elemOpts)
					}
				}
			}
		}
	}

	if encoder == nil {
		return nil, syntaxError("invalid Go type: %s", value.Type())
	}
	raw.Content, err = encoder(value)

	return raw, err
}

// applyOptions modifies a raw value based on the given options.
func (ctx *Context) applyOptions(value reflect.Value, raw *rawValue, opts *fieldOptions) (*rawValue, error) {
	// Change sequence to set
	if opts.set {
		if raw.Class != classUniversal || raw.Tag != tagSequence {
			return nil, syntaxError("Go type '%s' does not accept the flag 'set'", value.Type())
		}
		raw.Tag = tagSet
	}

	// Check if this type is an Asn.1 choice
	if opts.choice != nil {
		entry, err := ctx.getChoiceByType(*opts.choice, value.Type())
		if err != nil {
			return nil, err
		}
		raw, err = ctx.applyOptions(value, raw, entry.opts)
		// applyOptions returns a nil rawValue together with its error, so skipping
		// this check does not merely lose the error: the assignments below then
		// dereference nil and panic. Reachable whenever a choice entry's own options
		// fail validation.
		if err != nil {
			return nil, err
		}
		raw.Class = entry.class
		raw.Tag = entry.tag
	}

	// Add an enclosing tag
	if opts.explicit {
		if opts.tag == nil {
			return nil, syntaxError(
				"invalid flag 'explicit' without tag on Go type '%s'",
				value.Type())
		}
		content, err := raw.encode()
		if err != nil {
			return nil, err
		}
		raw = &rawValue{}
		raw.Constructed = true
		raw.Content = content
	}

	// Change tag
	if opts.tag != nil {
		raw.Class = classContextSpecific
		raw.Tag = uint(*opts.tag)
	}
	// Change class
	if opts.universal {
		raw.Class = classUniversal
	}
	if opts.application {
		raw.Class = classApplication
	}

	// Use the indefinite length encoding
	if opts.indefinite {
		if !raw.Constructed {
			return nil, syntaxError(
				"invalid flag 'indefinite' on Go type: %s",
				value.Type())
		}
		raw.Indefinite = true
	}

	return raw, nil
}

// isEmpty checks is a value is empty.
func isEmpty(value reflect.Value) bool {
	defaultValue := reflect.Zero(value.Type())
	return reflect.DeepEqual(value.Interface(), defaultValue.Interface())
}

// isFieldExported checks is the field name starts with a capital letter.
func isFieldExported(field reflect.StructField) bool {
	return unicode.IsUpper([]rune(field.Name)[0])
}

// getRawValuesFromFields encodes each valid field ofa struct value and returns
// a slice of raw values.
func (ctx *Context) getRawValuesFromFields(value reflect.Value) ([]*rawValue, error) {
	// Encode each child to a raw value
	children := []*rawValue{}
	for i := 0; i < value.NumField(); i++ {
		fieldValue := value.Field(i)
		fieldStruct := value.Type().Field(i)
		// Ignore field that are not exported (that starts with lowercase)
		if isFieldExported(fieldStruct) {
			tag := fieldStruct.Tag.Get(tagKey)
			opts, err := parseOptions(tag)
			if err != nil {
				return nil, err
			}
			raw, err := ctx.encode(fieldValue, opts)
			if err != nil {
				return nil, err
			}
			children = append(children, raw)
		}
	}
	return children, nil
}

// encodeRawValues is a helper function to encode raw value in sequence.
func (ctx *Context) encodeRawValues(values ...*rawValue) ([]byte, error) {
	content := []byte{}
	for _, raw := range values {
		buf, err := raw.encode()
		if err != nil {
			return nil, err
		}
		content = append(content, buf...)
	}
	return content, nil
}

// encodeStruct encodes structs fields in order.
func (ctx *Context) encodeStruct(value reflect.Value) ([]byte, error) {
	// Encode each child to a raw value
	children, err := ctx.getRawValuesFromFields(value)
	if err != nil {
		return nil, err
	}
	return ctx.encodeRawValues(children...)
}

// encodeStructAsSet works similarly to encodeStruct, but in Der mode the
// fields are encoded in ascending order of their tags.
func (ctx *Context) encodeStructAsSet(value reflect.Value) ([]byte, error) {
	// Encode each child to a raw value
	children, err := ctx.getRawValuesFromFields(value)
	if err != nil {
		return nil, err
	}
	// Sort if necessary
	if ctx.der.encoding {
		sort.Sort(rawValueSlice(children))
	}
	return ctx.encodeRawValues(children...)
}

// encodeSlice encodes a slice or array as a sequence of values.
func (ctx *Context) encodeSlice(value reflect.Value) ([]byte, error) {
	return ctx.encodeSliceWithOptions(value, &fieldOptions{})
}

// encodeSliceWithOptions encodes a slice or array as a sequence of values, applying
// elemOpts to each element.
//
// LOCAL PATCH (omec/li) 7/8: upstream's encodeSlice recursed into its elements with
// an empty options string, so a SEQUENCE OF CHOICE could not be expressed — the
// CHOICE never reached the elements, and was instead resolved against the slice
// type itself, which has no registered alternative.
func (ctx *Context) encodeSliceWithOptions(value reflect.Value, elemOpts *fieldOptions) ([]byte, error) {
	content := []byte{}
	for i := 0; i < value.Len(); i++ {
		itemValue := value.Index(i)
		raw, err := ctx.encode(itemValue, elemOpts)
		if err != nil {
			return nil, err
		}
		if raw == nil {
			// An element cannot be absent: optionality belongs to the sequence.
			return nil, syntaxError("missing value in sequence of '%s'", value.Type())
		}
		childBytes, err := raw.encode()
		if err != nil {
			return nil, err
		}
		content = append(content, childBytes...)
	}
	return content, nil
}
