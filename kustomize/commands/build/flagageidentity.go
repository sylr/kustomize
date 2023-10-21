// Copyright 2019 The Kubernetes Authors.
// SPDX-License-Identifier: Apache-2.0

package build

import (
	"github.com/spf13/pflag"
	"sigs.k8s.io/kustomize/api/kv"
)

func AddFlagAGEIdentities(set *pflag.FlagSet) {
	set.StringArrayVar(
		&kv.AgeIdentityFiles,
		"age-identity",
		[]string{},
		"add age identity file(s)")
}
