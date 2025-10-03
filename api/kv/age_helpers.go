package kv

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"

	"go.yaml.in/yaml/v3"
	"golang.org/x/term"
	yage "sylr.dev/yaml/age/v3"
)

type ageIdentityFiles map[string]age.Identity
type ageIdentityCache map[[sha256.Size]byte]age.Identity

var (
	sshAgeIdentityFiles        ageIdentityFiles = make(ageIdentityFiles)
	sshAgeIdentitiesCache      ageIdentityCache = make(ageIdentityCache)
	sshAgeIdentitiesCacheMutex sync.RWMutex     = sync.RWMutex{}
)

func decryptValueWithAge(value []byte, ids []age.Identity) ([]byte, error) {
	if len(ids) == 0 {
		if NoAgeDecryption {
			return value, nil
		}
	}

	var r io.Reader
	if bytes.HasPrefix(value, []byte(armor.Header)) {
		rr := bytes.NewBuffer(value)
		r = armor.NewReader(rr)
	} else {
		r = bytes.NewBuffer(value)
	}

	rd, err := age.Decrypt(r, ids...)
	if err != nil {
		if errors.Is(err, &age.NoIdentityMatchError{}) {
			if NoAgeDecryption {
				// No identities matched, but decryption is disabled, so just return the original content.
				return value, nil
			} else {
				return value, err
			}
		}
		return value, err
	}
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(rd)
	if err != nil {
		return value, err
	}
	value = buf.Bytes()

	return value, nil
}

func decryptInPlaceYAMLWithAge(value []byte, ids []age.Identity) ([]byte, error) {
	if NoAgeDecryption {
		return value, nil
	}

	in := bytes.NewBuffer(value)

	node := yaml.Node{}
	w := yage.Wrapper{
		Value:      &node,
		Identities: ids,
	}

	out := new(bytes.Buffer)
	decoder := yaml.NewDecoder(in)
	encoder := yaml.NewEncoder(out)
	encoder.SetIndent(2)

	for {
		err := decoder.Decode(&w)

		if err == io.EOF {
			break
		} else if errors.Is(err, &age.NoIdentityMatchError{}) {
			if NoAgeDecryption {
				// No identities matched, but decryption is disabled, so just return the original content.
				return value, nil
			} else {
				return value, err
			}
		} else if err != nil {
			return value, err
		}

		err = encoder.Encode(&node)

		if err != nil {
			return value, err
		}
	}

	return out.Bytes(), nil
}

// Following code has been copied from:
// - https://github.com/FiloSottile/age/blob/31e0d226807f679cce89b67dfde6201b62582158/cmd/age/parse.go
// - https://github.com/FiloSottile/age/blob/31e0d226807f679cce89b67dfde6201b62582158/cmd/age/encrypted_keys.go

func parseSSHIdentity(name string, pemBytes []byte) ([]age.Identity, error) {
	if id := getSSHAgeIdentityFromCache(pemBytes); id != nil {
		return []age.Identity{id}, nil
	}

	id, err := agessh.ParseIdentity(pemBytes)
	if sshErr, ok := err.(*ssh.PassphraseMissingError); ok {
		if NotInteractive {
			return nil, fmt.Errorf("key %q password protected but we are in non interactive mode", name)
		}
		pubKey := sshErr.PublicKey
		if pubKey == nil {
			pubKey, err = readPubFile(name)
			if err != nil {
				return nil, err
			}
		}
		passphrasePrompt := func() ([]byte, error) {
			fmt.Fprintf(os.Stderr, "Enter passphrase for %q: ", name)
			pass, err := readPassphrase()
			if err != nil {
				return nil, fmt.Errorf("could not read passphrase for %q: %v", name, err)
			}
			return pass, nil
		}
		id, err = agessh.NewEncryptedSSHIdentity(pubKey, pemBytes, passphrasePrompt)
		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, fmt.Errorf("malformed SSH identity in %q: %v", name, err)
	}

	// Only cache keys in interactive mode because we probably don't want to keep
	// in memory unlocked ssh private keys.
	if !NotInteractive {
		addSSHAgeIdentityToCache(name, pemBytes, id)
	}

	return []age.Identity{id}, nil
}

func readPubFile(name string) (ssh.PublicKey, error) {
	if name == "-" {
		return nil, fmt.Errorf(`failed to obtain public key for "-" SSH key
Use a file for which the corresponding ".pub" file exists, or convert the private key to a modern format with "ssh-keygen -p -m RFC4716"`)
	}
	f, err := os.Open(name + ".pub")
	if err != nil {
		return nil, fmt.Errorf(`failed to obtain public key for %q SSH key: %v
Ensure %q exists, or convert the private key %q to a modern format with "ssh-keygen -p -m RFC4716"`, name, err, name+".pub", name)
	}
	defer f.Close()
	contents, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", name+".pub", err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(contents)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %v", name+".pub", err)
	}
	return pubKey, nil
}

func readPassphrase() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nil, fmt.Errorf("standard input is not available or not a terminal, and opening /dev/tty failed: %v", err)
		}
		defer tty.Close()
		fd = int(tty.Fd())
	}
	defer fmt.Fprintf(os.Stderr, "\n")
	p, err := term.ReadPassword(fd)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func getSSHAgeIdentityFromCacheByPath(path string) age.Identity {
	sshAgeIdentitiesCacheMutex.RLock()
	defer sshAgeIdentitiesCacheMutex.RUnlock()

	if id, ok := sshAgeIdentityFiles[path]; ok {
		return id
	}

	return nil
}

func getSSHAgeIdentityFromCache(pemBytes []byte) age.Identity {
	sha256 := sha256.Sum256(pemBytes)

	sshAgeIdentitiesCacheMutex.RLock()
	defer sshAgeIdentitiesCacheMutex.RUnlock()

	if id, ok := sshAgeIdentitiesCache[sha256]; ok {
		return id
	}

	return nil
}

func addSSHAgeIdentityToCache(name string, pemBytes []byte, id age.Identity) {
	sha256 := sha256.Sum256(pemBytes)

	sshAgeIdentitiesCacheMutex.Lock()
	defer sshAgeIdentitiesCacheMutex.Unlock()

	sshAgeIdentitiesCache[sha256] = id
	sshAgeIdentityFiles[name] = id
}
