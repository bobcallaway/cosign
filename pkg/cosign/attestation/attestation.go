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

package attestation

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	attestationv1 "github.com/in-toto/attestation/go/v1"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsav02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	slsav1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// CosignCustomProvenanceV01 specifies the type of the Predicate.
	CosignCustomProvenanceV01 = "https://cosign.sigstore.dev/attestation/v1"

	// CosignVulnProvenanceV01 specifies the type of VulnerabilityScan Predicate
	CosignVulnProvenanceV01 = "https://cosign.sigstore.dev/attestation/vuln/v1"

	// OpenVexNamespace holds the URI of the OpenVEX context to identify its
	// predicate type. More info about the specification can be found at
	// https://github.com/openvex/spec and the attestation spec is found here:
	// https://github.com/openvex/spec/blob/main/ATTESTING.md
	OpenVexNamespace = "https://openvex.dev/ns"
)

// CosignPredicate specifies the format of the Custom Predicate.
type CosignPredicate struct {
	Data      interface{}
	Timestamp string
}

// VulnPredicate specifies the format of the Vulnerability Scan Predicate
type CosignVulnPredicate struct {
	Invocation Invocation `json:"invocation"`
	Scanner    Scanner    `json:"scanner"`
	Metadata   Metadata   `json:"metadata"`
}

// I think this will be moving to upstream in-toto in the fullness of time
// but creating it here for now so that we have a way to deserialize it
// as a InToto Statement
// https://github.com/in-toto/attestation/issues/58
/* type CosignVulnStatement struct {
	in_toto.StatementHeader
	Predicate CosignVulnPredicate `json:"predicate"`
} */

type Invocation struct {
	Parameters interface{} `json:"parameters"`
	URI        string      `json:"uri"`
	EventID    string      `json:"event_id"`
	BuilderID  string      `json:"builder.id"`
}

type DB struct {
	URI     string `json:"uri"`
	Version string `json:"version"`
}

type Scanner struct {
	URI     string      `json:"uri"`
	Version string      `json:"version"`
	DB      DB          `json:"db"`
	Result  interface{} `json:"result"`
}

type Metadata struct {
	ScanStartedOn  time.Time `json:"scanStartedOn"`
	ScanFinishedOn time.Time `json:"scanFinishedOn"`
}

// GenerateOpts specifies the options of the Statement generator.
type GenerateOpts struct {
	// Predicate is the source of bytes (e.g. a file) to use as the statement's predicate.
	Predicate io.Reader
	// Type is the pre-defined enums (provenance|link|spdx).
	// default: custom
	Type string
	// Digest of the Image reference.
	Digest string
	// Repo context of the reference.
	Repo string

	// Function to return the time to set
	Time func() time.Time
}

// GenerateStatement returns an in-toto statement based on the provided
// predicate type (custom|slsaprovenance|slsaprovenance02|slsaprovenance1|spdx|spdxjson|cyclonedx|link).
func GenerateStatement(opts GenerateOpts) (*attestationv1.Statement, error) {
	predicate, err := io.ReadAll(opts.Predicate)
	if err != nil {
		return nil, err
	}

	switch opts.Type {
	case "slsaprovenance":
		return generateSLSAProvenanceStatementSLSA02(predicate, opts.Digest, opts.Repo)
	case "slsaprovenance02":
		return generateSLSAProvenanceStatementSLSA02(predicate, opts.Digest, opts.Repo)
	case "slsaprovenance1":
		return generateSLSAProvenanceStatementSLSA1(predicate, opts.Digest, opts.Repo)
	case "spdx":
		return generateSPDXStatement(predicate, opts.Digest, opts.Repo, false)
	case "spdxjson":
		return generateSPDXStatement(predicate, opts.Digest, opts.Repo, true)
	case "cyclonedx":
		return generateCycloneDXStatement(predicate, opts.Digest, opts.Repo)
	case "link":
		return generateLinkStatement(predicate, opts.Digest, opts.Repo)
	case "vuln":
		return generateVulnStatement(predicate, opts.Digest, opts.Repo)
	case "openvex":
		return generateOpenVexStatement(predicate, opts.Digest, opts.Repo)
	default:
		stamp := timestamp(opts)
		predicateType := customType(opts)
		return generateCustomStatement(predicate, predicateType, opts.Digest, opts.Repo, stamp)
	}
}

func generateVulnStatement(rawPayload []byte, digest string, repo string) (*attestationv1.Statement, error) {
	stmt := generateStatementHeader(digest, repo, CosignVulnProvenanceV01)
	var predicate CosignVulnPredicate
	if err := json.Unmarshal(rawPayload, &predicate); err != nil {
		return nil, fmt.Errorf("unmarshaling vuln predicate: %w", err)
	}

	predicateBytes, err := json.Marshal(predicate)
	if err != nil {
		return nil, fmt.Errorf("marshaling vuln predicate to JSON: %w", err)
	}

	var predicateStruct structpb.Struct
	if err := json.Unmarshal(predicateBytes, &predicateStruct); err != nil {
		return nil, fmt.Errorf("unmarshaling vuln predicate JSON to Struct: %w", err)
	}
	stmt.Predicate = &predicateStruct
	return stmt, nil
}

func timestamp(opts GenerateOpts) string {
	if opts.Time == nil {
		opts.Time = time.Now
	}
	now := opts.Time()
	return now.UTC().Format(time.RFC3339)
}

func customType(opts GenerateOpts) string {
	if opts.Type != "custom" {
		return opts.Type
	}
	return CosignCustomProvenanceV01
}

func generateStatementHeader(digest, repo, predicateType string) *attestationv1.Statement {
	stmt := &attestationv1.Statement{}
	stmt.Type = attestationv1.StatementTypeUri
	stmt.PredicateType = predicateType
	stmt.Subject = []*attestationv1.ResourceDescriptor{
		{
			Name: repo,
			Digest: map[string]string{
				"sha256": digest,
			},
		},
	}
	return stmt
}

func generateCustomStatement(rawPayload []byte, customType, digest, repo, timestamp string) (*attestationv1.Statement, error) {
	stmt := generateStatementHeader(digest, repo, customType)
	predicate, err := generateCustomPredicate(rawPayload, customType, timestamp)
	if err != nil {
		return nil, fmt.Errorf("generating custom predicate: %w", err)
	}

	predicateBytes, err := json.Marshal(predicate)
	if err != nil {
		return nil, fmt.Errorf("marshaling custom predicate to JSON: %w", err)
	}

	var predicateStruct structpb.Struct
	if err := json.Unmarshal(predicateBytes, &predicateStruct); err != nil {
		return nil, fmt.Errorf("unmarshaling custom predicate JSON to Struct: %w", err)
	}
	stmt.Predicate = &predicateStruct
	return stmt, nil
}

func generateCustomPredicate(rawPayload []byte, customType, timestamp string) (interface{}, error) {
	if customType == CosignCustomProvenanceV01 {
		return &CosignPredicate{
			Data:      string(rawPayload),
			Timestamp: timestamp,
		}, nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(rawPayload, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON payload for predicate type %s: %w", customType, err)
	}

	return result, nil
}

func generateSLSAProvenanceStatementSLSA02(rawPayload []byte, digest string, repo string) (*attestationv1.Statement, error) {
	stmt := generateStatementHeader(digest, repo, slsav02.PredicateSLSAProvenance)
	var predicate slsav02.ProvenancePredicate
	err := checkRequiredJSONFields(rawPayload, reflect.TypeOf(predicate))
	if err != nil {
		return nil, fmt.Errorf("checking required JSON fields for SLSA v0.2 provenance predicate: %w", err)
	}
	if err := json.Unmarshal(rawPayload, &predicate); err != nil {
		return nil, fmt.Errorf("unmarshaling SLSA v0.2 provenance predicate: %w", err)
	}

	predicateBytes, err := json.Marshal(predicate)
	if err != nil {
		return nil, fmt.Errorf("marshaling SLSA v0.2 predicate to JSON: %w", err)
	}

	var predicateStruct structpb.Struct
	if err := json.Unmarshal(predicateBytes, &predicateStruct); err != nil {
		return nil, fmt.Errorf("unmarshaling SLSA v0.2 predicate JSON to Struct: %w", err)
	}
	stmt.Predicate = &predicateStruct
	return stmt, nil
}

func generateSLSAProvenanceStatementSLSA1(rawPayload []byte, digest string, repo string) (*attestationv1.Statement, error) {
	stmt := generateStatementHeader(digest, repo, slsav1.PredicateSLSAProvenance)
	var predicate slsav1.ProvenancePredicate
	err := checkRequiredJSONFields(rawPayload, reflect.TypeOf(predicate))
	if err != nil {
		return nil, fmt.Errorf("checking required JSON fields for SLSA v1 provenance predicate: %w", err)
	}
	if err := json.Unmarshal(rawPayload, &predicate); err != nil {
		return nil, fmt.Errorf("unmarshaling SLSA v1 provenance predicate: %w", err)
	}

	predicateBytes, err := json.Marshal(predicate)
	if err != nil {
		return nil, fmt.Errorf("marshaling SLSA v1 predicate to JSON: %w", err)
	}

	var predicateStruct structpb.Struct
	if err := json.Unmarshal(predicateBytes, &predicateStruct); err != nil {
		return nil, fmt.Errorf("unmarshaling SLSA v1 predicate JSON to Struct: %w", err)
	}
	stmt.Predicate = &predicateStruct
	return stmt, nil
}

func generateLinkStatement(rawPayload []byte, digest string, repo string) (*attestationv1.Statement, error) {
	stmt := generateStatementHeader(digest, repo, intoto.PredicateLinkV1)
	var linkRef intoto.Link
	err := checkRequiredJSONFields(rawPayload, reflect.TypeOf(linkRef))
	if err != nil {
		return nil, fmt.Errorf("checking required JSON fields for link predicate: %w", err)
	}
	if err := json.Unmarshal(rawPayload, &linkRef); err != nil {
		return nil, fmt.Errorf("unmarshaling link predicate: %w", err)
	}

	predicateBytes, err := json.Marshal(linkRef)
	if err != nil {
		return nil, fmt.Errorf("marshaling link predicate to JSON: %w", err)
	}

	var predicateStruct structpb.Struct
	if err := json.Unmarshal(predicateBytes, &predicateStruct); err != nil {
		return nil, fmt.Errorf("unmarshaling link predicate JSON to Struct: %w", err)
	}
	stmt.Predicate = &predicateStruct
	return stmt, nil
}

func generateOpenVexStatement(rawPayload []byte, digest string, repo string) (*attestationv1.Statement, error) {
	stmt := generateStatementHeader(digest, repo, OpenVexNamespace)
	var data interface{}
	if err := json.Unmarshal(rawPayload, &data); err != nil {
		return nil, fmt.Errorf("unmarshaling OpenVEX predicate: %w", err)
	}

	predicateBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling OpenVEX predicate to JSON: %w", err)
	}

	var predicateStruct structpb.Struct
	if err := json.Unmarshal(predicateBytes, &predicateStruct); err != nil {
		return nil, fmt.Errorf("unmarshaling OpenVEX predicate JSON to Struct: %w", err)
	}
	stmt.Predicate = &predicateStruct
	return stmt, nil
}

func generateSPDXStatement(rawPayload []byte, digest string, repo string, parseJSON bool) (*attestationv1.Statement, error) {
	stmt := generateStatementHeader(digest, repo, intoto.PredicateSPDX)
	var data interface{}
	if parseJSON {
		if err := json.Unmarshal(rawPayload, &data); err != nil {
			return nil, fmt.Errorf("unmarshaling SPDX JSON predicate: %w", err)
		}
	} else {
		data = string(rawPayload)
	}

	predicateBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling SPDX predicate to JSON: %w", err)
	}

	var predicateStruct structpb.Struct
	if err := json.Unmarshal(predicateBytes, &predicateStruct); err != nil {
		return nil, fmt.Errorf("unmarshaling SPDX predicate JSON to Struct: %w", err)
	}
	stmt.Predicate = &predicateStruct
	return stmt, nil
}

func generateCycloneDXStatement(rawPayload []byte, digest string, repo string) (*attestationv1.Statement, error) {
	stmt := generateStatementHeader(digest, repo, intoto.PredicateCycloneDX)
	var data interface{}
	if err := json.Unmarshal(rawPayload, &data); err != nil {
		return nil, fmt.Errorf("unmarshaling CycloneDX predicate: %w", err)
	}

	predicateBytes, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshaling CycloneDX predicate to JSON: %w", err)
	}

	var predicateStruct structpb.Struct
	if err := json.Unmarshal(predicateBytes, &predicateStruct); err != nil {
		return nil, fmt.Errorf("unmarshaling CycloneDX predicate JSON to Struct: %w", err)
	}
	stmt.Predicate = &predicateStruct
	return stmt, nil
}

func checkRequiredJSONFields(rawPayload []byte, typ reflect.Type) error {
	var tmp map[string]interface{}
	if err := json.Unmarshal(rawPayload, &tmp); err != nil {
		return err
	}
	// Create list of json tags, e.g. `json:"_type"`
	attributeCount := typ.NumField()
	allFields := make([]string, 0)
	for i := 0; i < attributeCount; i++ {
		jsonTagFields := strings.SplitN(typ.Field(i).Tag.Get("json"), ",", 2)
		if len(jsonTagFields) < 2 {
			allFields = append(allFields, jsonTagFields[0])
		}
	}

	// Assert that there's a key in the passed map for each tag
	for _, field := range allFields {
		if _, ok := tmp[field]; !ok {
			return fmt.Errorf("required field %s missing", field)
		}
	}
	return nil
}
