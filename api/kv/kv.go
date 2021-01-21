// Copyright 2019 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package kv

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"filippo.io/age"
	"filippo.io/age/armor"

	"github.com/pkg/errors"

	"sigs.k8s.io/kustomize/api/ifc"
	"sigs.k8s.io/kustomize/api/types"
)

var utf8bom = []byte{0xEF, 0xBB, 0xBF}

// loader reads and validates KV pairs.
type loader struct {
	// Used to read the filesystem.
	ldr ifc.Loader

	// Used to get age identities
	rootLdr ifc.Loader

	// Used to validate various k8s data fields.
	validator ifc.Validator
}

func NewLoader(ldr ifc.Loader, rootLdr ifc.Loader, v ifc.Validator) ifc.KvLoader {
	return &loader{ldr: ldr, rootLdr: rootLdr, validator: v}
}

func (kvl *loader) Validator() ifc.Validator {
	return kvl.validator
}

func (kvl *loader) Load(
	args types.KvPairSources) (all []types.Pair, err error) {
	ids, err := kvl.getAgeIdentities(args.AgeIdentitySources)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf(
			"age identity source files: %v",
			args.AgeIdentitySources))
	}

	pairs, err := kvl.keyValuesFromEnvFiles(args.EnvSources, ids)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf(
			"env source files: %v",
			args.EnvSources))
	}
	all = append(all, pairs...)

	pairs, err = keyValuesFromLiteralSources(args.LiteralSources, ids)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf(
			"literal sources %v", args.LiteralSources))
	}
	all = append(all, pairs...)

	pairs, err = kvl.keyValuesFromFileSources(args.FileSources, ids)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf(
			"file sources: %v", args.FileSources))
	}
	return append(all, pairs...), nil
}

func (kvl *loader) getAgeIdentities(sources []string) ([]age.Identity, error) {
	var ids []age.Identity
	if len(sources) > 0 {
		for _, path := range sources {
			path, err := filepath.Abs(path)
			if err != nil {
				return nil, err
			}
			content, err := kvl.rootLdr.Load(path)
			if err != nil {
				return nil, err
			}
			fd := bytes.NewBuffer(content)
			id, err := age.ParseIdentities(fd)
			if err != nil {
				return nil, err
			}
			ids = append(ids, id...)
		}
	}

	for _, path := range []string{
		os.ExpandEnv("$HOME/.ssh/id_rsa"),
		os.ExpandEnv("$HOME/.ssh/id_ed25519"),
	} {
		content, err := ioutil.ReadFile(path)
		if err != nil {
			continue
		}

		sshids, err := parseSSHIdentity(path, content)
		if err != nil {
			// If the key is explicitly requested, this error will be caught
			// below, otherwise ignore it silently.
			continue
		}
		ids = append(ids, sshids...)
	}
	return ids, nil
}

func keyValuesFromLiteralSources(sources []string, ids []age.Identity) ([]types.Pair, error) {
	var kvs []types.Pair
	for _, s := range sources {
		k, v, err := parseLiteralSource(s)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(k, ".age") {
			k = strings.TrimRight(k, ".age")
			content := []byte(v)
			if strings.HasSuffix(k, ".yaml") || strings.HasSuffix(k, ".yml") {
				content, err = decryptInlineYAMLWithAge(content, ids)
			} else {
				content, err = decryptValueWithAge(content, ids)
			}
			if err != nil {
				return nil, err
			}
			v = string(content)
		}
		kvs = append(kvs, types.Pair{Key: k, Value: v})
	}
	return kvs, nil
}

func (kvl *loader) keyValuesFromFileSources(sources []string, ids []age.Identity) ([]types.Pair, error) {
	var kvs []types.Pair
	for _, s := range sources {
		k, fPath, err := parseFileSource(s)
		if err != nil {
			return nil, err
		}
		content, err := kvl.ldr.Load(fPath)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(fPath, ".age") {
			k = strings.TrimRight(k, ".age")

			if (strings.HasSuffix(k, ".yaml") || strings.HasSuffix(k, ".yml")) &&
				!bytes.HasPrefix(content, []byte(armor.Header)) {
				// If key has .yaml or .yml extension and has no age armor header
				// then we try inline decrypting of the file.
				content, err = decryptInlineYAMLWithAge(content, ids)
			} else {
				content, err = decryptValueWithAge(content, ids)
			}
			if err != nil {
				return nil, err
			}
		}
		kvs = append(kvs, types.Pair{Key: k, Value: string(content)})
	}
	return kvs, nil
}

func (kvl *loader) keyValuesFromEnvFiles(paths []string, ids []age.Identity) ([]types.Pair, error) {
	var kvs []types.Pair
	for _, p := range paths {
		content, err := kvl.ldr.Load(p)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(p, ".age") {
			content, err = decryptValueWithAge(content, ids)
			if err != nil {
				return nil, err
			}
		}
		more, err := kvl.keyValuesFromLines(content)
		if err != nil {
			return nil, err
		}
		kvs = append(kvs, more...)
	}
	return kvs, nil
}

// keyValuesFromLines parses given content in to a list of key-value pairs.
func (kvl *loader) keyValuesFromLines(content []byte) ([]types.Pair, error) {
	var kvs []types.Pair

	scanner := bufio.NewScanner(bytes.NewReader(content))
	currentLine := 0
	for scanner.Scan() {
		// Process the current line, retrieving a key/value pair if
		// possible.
		scannedBytes := scanner.Bytes()
		kv, err := kvl.keyValuesFromLine(scannedBytes, currentLine)
		if err != nil {
			return nil, err
		}
		currentLine++

		if len(kv.Key) == 0 {
			// no key means line was empty or a comment
			continue
		}

		kvs = append(kvs, kv)
	}
	return kvs, nil
}

// KeyValuesFromLine returns a kv with blank key if the line is empty or a comment.
// The value will be retrieved from the environment if necessary.
func (kvl *loader) keyValuesFromLine(line []byte, currentLine int) (types.Pair, error) {
	kv := types.Pair{}

	if !utf8.Valid(line) {
		return kv, fmt.Errorf("line %d has invalid utf8 bytes : %v", line, string(line))
	}

	// We trim UTF8 BOM from the first line of the file but no others
	if currentLine == 0 {
		line = bytes.TrimPrefix(line, utf8bom)
	}

	// trim the line from all leading whitespace first
	line = bytes.TrimLeftFunc(line, unicode.IsSpace)

	// If the line is empty or a comment, we return a blank key/value pair.
	if len(line) == 0 || line[0] == '#' {
		return kv, nil
	}

	data := strings.SplitN(string(line), "=", 2)
	key := data[0]
	if err := kvl.validator.IsEnvVarName(key); err != nil {
		return kv, err
	}

	if len(data) == 2 {
		kv.Value = data[1]
	} else {
		// No value (no `=` in the line) is a signal to obtain the value
		// from the environment.
		kv.Value = os.Getenv(key)
	}
	kv.Key = key
	return kv, nil
}

// ParseFileSource parses the source given.
//
//  Acceptable formats include:
//   1.  source-path: the basename will become the key name
//   2.  source-name=source-path: the source-name will become the key name and
//       source-path is the path to the key file.
//
// Key names cannot include '='.
func parseFileSource(source string) (keyName, filePath string, err error) {
	numSeparators := strings.Count(source, "=")
	switch {
	case numSeparators == 0:
		return path.Base(source), source, nil
	case numSeparators == 1 && strings.HasPrefix(source, "="):
		return "", "", fmt.Errorf("key name for file path %v missing", strings.TrimPrefix(source, "="))
	case numSeparators == 1 && strings.HasSuffix(source, "="):
		return "", "", fmt.Errorf("file path for key name %v missing", strings.TrimSuffix(source, "="))
	case numSeparators > 1:
		return "", "", errors.New("key names or file paths cannot contain '='")
	default:
		components := strings.Split(source, "=")
		return components[0], components[1], nil
	}
}

// ParseLiteralSource parses the source key=val pair into its component pieces.
// This functionality is distinguished from strings.SplitN(source, "=", 2) since
// it returns an error in the case of empty keys, values, or a missing equals sign.
func parseLiteralSource(source string) (keyName, value string, err error) {
	// leading equal is invalid
	if strings.Index(source, "=") == 0 {
		return "", "", fmt.Errorf("invalid literal source %v, expected key=value", source)
	}
	// split after the first equal (so values can have the = character)
	items := strings.SplitN(source, "=", 2)
	if len(items) != 2 {
		return "", "", fmt.Errorf("invalid literal source %v, expected key=value", source)
	}
	return items[0], strings.Trim(items[1], "\"'"), nil
}
