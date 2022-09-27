//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package options

import (
	"github.com/spf13/cobra"
)

// VerifyOptions is the top level wrapper for the `verify` command.
type VerifyOptions struct {
	Key          string
	CheckClaims  bool
	Attachment   string
	Output       string
	SignatureRef string
	LocalImage   bool

	SecurityKey     SecurityKeyOptions
	CertVerify      CertVerifyOptions
	Rekor           RekorOptions
	Registry        RegistryOptions
	SignatureDigest SignatureDigestOptions
	AnnotationOptions
}

var _ Interface = (*VerifyOptions)(nil)

// AddFlags implements Interface
func (o *VerifyOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.CertVerify.AddFlags(cmd)
	o.Registry.AddFlags(cmd)
	o.SignatureDigest.AddFlags(cmd)
	o.AnnotationOptions.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the public key file, KMS URI or Kubernetes Secret")
	_ = cmd.Flags().SetAnnotation("key", cobra.BashCompFilenameExt, []string{})

	cmd.Flags().BoolVar(&o.CheckClaims, "check-claims", true,
		"whether to check the claims found")

	cmd.Flags().StringVar(&o.Attachment, "attachment", "",
		"related image attachment to sign (sbom), default none")

	cmd.Flags().StringVarP(&o.Output, "output", "o", "json",
		"output format for the signing image information (json|text)")

	cmd.Flags().StringVar(&o.SignatureRef, "signature", "",
		"signature content or path or remote URL")

	cmd.Flags().BoolVar(&o.LocalImage, "local-image", false,
		"whether the specified image is a path to an image saved locally via 'cosign save'")
}

// VerifyAttestationOptions is the top level wrapper for the `verify attestation` command.
type VerifyAttestationOptions struct {
	Key         string
	CheckClaims bool
	Output      string

	SecurityKey SecurityKeyOptions
	Rekor       RekorOptions
	CertVerify  CertVerifyOptions
	Registry    RegistryOptions
	Predicate   PredicateRemoteOptions
	Policies    []string
	LocalImage  bool
}

var _ Interface = (*VerifyAttestationOptions)(nil)

// AddFlags implements Interface
func (o *VerifyAttestationOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.CertVerify.AddFlags(cmd)
	o.Registry.AddFlags(cmd)
	o.Predicate.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the public key file, KMS URI or Kubernetes Secret")

	cmd.Flags().BoolVar(&o.CheckClaims, "check-claims", true,
		"whether to check the claims found")

	cmd.Flags().StringSliceVar(&o.Policies, "policy", nil,
		"specify CUE or Rego files will be using for validation")

	cmd.Flags().StringVarP(&o.Output, "output", "o", "json",
		"output format for the signing image information (json|text)")

	cmd.Flags().BoolVar(&o.LocalImage, "local-image", false,
		"whether the specified image is a path to an image saved locally via 'cosign save'")
}

// VerifyBlobOptions is the top level wrapper for the `verify blob` command.
type VerifyBlobOptions struct {
	Key        string
	Signature  string
	BundlePath string

	SecurityKey SecurityKeyOptions
	CertVerify  CertVerifyOptions
	Rekor       RekorOptions
	Registry    RegistryOptions
}

var _ Interface = (*VerifyBlobOptions)(nil)

// AddFlags implements Interface
func (o *VerifyBlobOptions) AddFlags(cmd *cobra.Command) {
	o.SecurityKey.AddFlags(cmd)
	o.Rekor.AddFlags(cmd)
	o.CertVerify.AddFlags(cmd)
	o.Registry.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Key, "key", "",
		"path to the public key file, KMS URI or Kubernetes Secret")

	cmd.Flags().StringVar(&o.Signature, "signature", "",
		"signature content or path or remote URL")

	cmd.Flags().StringVar(&o.BundlePath, "bundle", "",
		"path to bundle FILE")
}

// VerifyBlobOptions is the top level wrapper for the `verify blob` command.
type VerifyDockerfileOptions struct {
	VerifyOptions
	BaseImageOnly bool
}

var _ Interface = (*VerifyDockerfileOptions)(nil)

// AddFlags implements Interface
func (o *VerifyDockerfileOptions) AddFlags(cmd *cobra.Command) {
	o.VerifyOptions.AddFlags(cmd)

	cmd.Flags().BoolVar(&o.BaseImageOnly, "base-image-only", false,
		"only verify the base image (the last FROM image in the Dockerfile)")
}
