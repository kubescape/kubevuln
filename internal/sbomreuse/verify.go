package sbomreuse

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
)

const StatementType = "https://in-toto.io/Statement/v1"
const PredicateType = "https://anchore.com/syft"

type statement struct {
	Type          string             `json:"_type"`
	Subject       []statementSubject `json:"subject"`
	PredicateType string             `json:"predicateType"`
	Predicate     json.RawMessage    `json:"predicate"`
}
type statementSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

func verify(ctx context.Context, envelope []byte, s subject, producer trust) (json.RawMessage, string, error) {
	var env dsse.Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, "", err
	}
	if env.PayloadType != ArtifactType || len(env.Signatures) == 0 || len(env.Signatures) > 8 {
		return nil, "", fmt.Errorf("unsupported DSSE envelope")
	}
	var verifiers []dsse.Verifier
	// Deterministic signer provenance when more than one approved key signed the envelope.
	ids := make([]string, 0, len(producer.keys))
	for id := range producer.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		v, err := signerverifier.NewED25519SignerVerifierFromSSLibKey(&signerverifier.SSLibKey{KeyID: id, KeyType: signerverifier.ED25519KeyType, KeyVal: signerverifier.KeyVal{Public: hex.EncodeToString(producer.keys[id])}})
		if err != nil {
			return nil, "", err
		}
		verifiers = append(verifiers, v)
	}
	v, err := dsse.NewEnvelopeVerifier(verifiers...)
	if err != nil {
		return nil, "", err
	}
	keys, payload, err := v.VerifyAndDecode(ctx, &env)
	if err != nil {
		return nil, "", fmt.Errorf("verifying inventory attestation: %w", err)
	}
	var st statement
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, "", err
	}
	if st.Type != StatementType || st.PredicateType != PredicateType || len(st.Subject) != 1 {
		return nil, "", fmt.Errorf("unsupported in-toto statement")
	}
	want := s.descriptor.Digest
	if st.Subject[0].Name != s.ref.Context().Name() || len(st.Subject[0].Digest) != 1 || st.Subject[0].Digest[want.Algorithm] != want.Hex {
		return nil, "", fmt.Errorf("signed image subject mismatch")
	}
	if len(st.Predicate) == 0 || string(st.Predicate) == "null" {
		return nil, "", fmt.Errorf("missing signed inventory")
	}
	return st.Predicate, keys[0].KeyID, nil
}
