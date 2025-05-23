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

package remote

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/sigstore/cosign/v2/pkg/oci"
	"github.com/sigstore/cosign/v2/pkg/oci/empty"
	"github.com/sigstore/cosign/v2/pkg/oci/internal/signature"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
)

const maxLayers = 1000

// Signatures fetches the signatures image represented by the named reference.
// If the tag is not found, this returns an empty oci.Signatures.
func Signatures(ref name.Reference, opts ...Option) (oci.Signatures, error) {
	o := makeOptions(ref.Context(), opts...)
	img, err := remoteImage(ref, o.ROpt...)
	var te *transport.Error
	if errors.As(err, &te) {
		if te.StatusCode != http.StatusNotFound {
			return nil, te
		}
		return empty.Signatures(), nil
	} else if err != nil {
		return nil, err
	}
	return &sigs{
		Image: img,
	}, nil
}

func Bundle(ref name.Reference, opts ...Option) (*sgbundle.Bundle, error) {
	o := makeOptions(ref.Context(), opts...)
	img, err := remoteImage(ref, o.ROpt...)
	if err != nil {
		return nil, err
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	if len(layers) != 1 {
		return nil, errors.New("expected exactly one layer")
	}
	mediaType, err := layers[0].MediaType()
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(string(mediaType), "application/vnd.dev.sigstore.bundle") {
		return nil, errors.New("expected bundle layer")
	}
	layer0, err := layers[0].Uncompressed()
	if err != nil {
		return nil, err
	}
	bundleBytes, err := io.ReadAll(layer0)
	if err != nil {
		return nil, err
	}
	b := &sgbundle.Bundle{}
	err = b.UnmarshalJSON(bundleBytes)
	if err != nil {
		return nil, err
	}
	if !b.MinVersion("v0.3") {
		return nil, errors.New("bundle version too old")
	}
	return b, nil
}

type sigs struct {
	v1.Image
}

// The wrapped Image implements ConfigLayer, but the wrapping hides that from typechecks in pkg/v1/remote.
// Make sigs explicitly implement ConfigLayer so that this returns a mountable config layer for pkg/v1/remote.
func (s *sigs) ConfigLayer() (v1.Layer, error) {
	return partial.ConfigLayer(s.Image)
}

var _ oci.Signatures = (*sigs)(nil)

// Get implements oci.Signatures
func (s *sigs) Get() ([]oci.Signature, error) {
	m, err := s.Manifest()
	if err != nil {
		return nil, err
	}
	numLayers := int64(len(m.Layers))
	if numLayers > maxLayers {
		return nil, oci.NewMaxLayersExceeded(numLayers, maxLayers)
	}
	signatures := make([]oci.Signature, 0, len(m.Layers))
	for _, desc := range m.Layers {
		layer, err := s.LayerByDigest(desc.Digest)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, signature.New(layer, desc))
	}
	return signatures, nil
}
