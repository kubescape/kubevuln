package sbomreuse

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/require"
)

func signStatement(t *testing.T, s subject, predicate []byte, key ed25519.PrivateKey) []byte {
	t.Helper()
	payload, err := json.Marshal(statement{Type: StatementType, PredicateType: PredicateType, Subject: []statementSubject{{Name: s.ref.Context().Name(), Digest: map[string]string{s.descriptor.Digest.Algorithm: s.descriptor.Digest.Hex}}}, Predicate: predicate})
	require.NoError(t, err)
	// Signing through the standard library independently checks compatibility with
	// the maintained DSSE verifier. Empty keyid lets verification identify the signer.
	env := dsse.Envelope{PayloadType: ArtifactType, Payload: base64.StdEncoding.EncodeToString(payload), Signatures: []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(key, dsse.PAE(ArtifactType, payload)))}}}
	b, err := json.Marshal(env)
	require.NoError(t, err)
	return b
}

func TestVerifySignedSubject(t *testing.T) {
	repo, c := testRegistry(t)
	ref := publishImage(t, repo, "amd64")
	s, err := c.resolve(ref, "")
	require.NoError(t, err)
	p, key := testPolicy(t, repo.Name())
	policy, err := CompilePolicy(p)
	require.NoError(t, err)
	env := signStatement(t, s, []byte(`{"artifacts":[]}`), key)
	predicate, signer, err := verify(context.Background(), env, s, policy.repositories[repo.Name()])
	require.NoError(t, err)
	require.NotEmpty(t, signer)
	require.JSONEq(t, `{"artifacts":[]}`, string(predicate))
	other, _ := testPolicy(t, repo.Name())
	otherPolicy, err := CompilePolicy(other)
	require.NoError(t, err)
	_, _, err = verify(context.Background(), env, s, otherPolicy.repositories[repo.Name()])
	require.Error(t, err)
	wrong := s
	wrong.descriptor.Digest.Hex = "0000000000000000000000000000000000000000000000000000000000000000"
	_, _, err = verify(context.Background(), env, wrong, policy.repositories[repo.Name()])
	require.ErrorContains(t, err, "subject")
	var tampered dsse.Envelope
	require.NoError(t, json.Unmarshal(env, &tampered))
	tampered.Payload = base64.StdEncoding.EncodeToString([]byte(`{}`))
	b, err := json.Marshal(tampered)
	require.NoError(t, err)
	_, _, err = verify(context.Background(), b, s, policy.repositories[repo.Name()])
	require.Error(t, err)
}
