package scanner

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
	sigs "github.com/sigstore/cosign/pkg/signature"
)

// VerifyCommand verifies a signature on a supplied container image
// nolint
type VerifyCommand struct {
	options.RegistryOptions
	CheckClaims                  bool
	KeyRef                       string
	CertRef                      string
	CertEmail                    string
	CertIdentity                 string
	CertOidcIssuer               string
	CertGithubWorkflowTrigger    string
	CertGithubWorkflowSha        string
	CertGithubWorkflowName       string
	CertGithubWorkflowRepository string
	CertGithubWorkflowRef        string
	CertChain                    string
	CertOidcProvider             string
	EnforceSCT                   bool
	Sk                           bool
	Slot                         string
	Output                       string
	RekorURL                     string
	Attachment                   string
	Annotations                  sigs.AnnotationsMap
	SignatureRef                 string
	HashAlgorithm                crypto.Hash
	LocalImage                   bool
}

// Exec runs the verification command
func verify(img string, key string) (bool, error) {

	co := &cosign.CheckOpts{}
	var ociremoteOpts []ociremote.Option
	attachment := ""

	pubKey, err := sigs.LoadPublicKeyRaw([]byte(key), crypto.SHA256)
	if err != nil {
		return false, fmt.Errorf("loading public key: %w", err)
	}
	pkcs11Key, ok := pubKey.(*pkcs11key.Key)
	if ok {
		defer pkcs11Key.Close()
	}
	co.SigVerifier = pubKey
	ref, err := name.ParseReference(img)
	if err != nil {
		return false, fmt.Errorf("parsing reference: %w", err)
	}
	ref, err = sign.GetAttachedImageRef(ref, attachment, ociremoteOpts...)
	if err != nil {
		return false, fmt.Errorf("resolving attachment type %s for image %s: %w", attachment, img, err)
	}

	_, _, err = cosign.VerifyImageSignatures(context.TODO(), ref, co)
	if err != nil {
		return false, fmt.Errorf("verifying signature: %w", err)
	}

	return true, nil
}

type controlSettingsForTrustedSigningKeys struct {
	Settings struct {
		TrustedSigningKeys []string `json:"trustedCosignPublicKeys"`
	} `json:"settings"`
}

// Get Kubescape control configuration
func GetKubescapeControlConfig(customerGUID string) ([]string, error) {

	// Call armoCustomerConfiguration API via HTTP
	resp, err := http.Get("https://api.armosec.io/api/v1/customerConfiguration?customerGUID=" + customerGUID)
	if err != nil {
		return nil, err
	}

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Convert response body to json
	var config controlSettingsForTrustedSigningKeys
	err = json.Unmarshal(body, &config)
	if err != nil {
		return nil, err
	}

	return config.Settings.TrustedSigningKeys, nil
}

// VerifyImageSignature verifies the signature of an image
func VerifyImageSignature(customerGUID string, imageRef string) (bool, error) {
	trustedKeys, err := GetKubescapeControlConfig(customerGUID)
	if err != nil {
		return false, err
	}
	for _, key := range trustedKeys {
		result, err := verify(imageRef, key)
		if err != nil && result == true {
			return true, nil
		}
	}
	return false, err
}

// Check if the image has signature
func CheckIfImageHasSignature(imageRef string) (bool, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return false, fmt.Errorf("parsing reference: %w", err)
	}
	sins, err := cosign.FetchSignaturesForReference(context.Background(), ref)
	if err != nil {
		return false, fmt.Errorf("fetching signatures: %w", err)
	}
	return len(sins) > 0, nil
}
