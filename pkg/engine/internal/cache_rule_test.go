package internal

import (
	"testing"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/stretchr/testify/assert"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func Test_attestorCacheRule_BindsMaterialNotName(t *testing.T) {
	withKey := func(key string) *kyvernov1.ImageVerification {
		return &kyvernov1.ImageVerification{
			Attestors: []kyvernov1.AttestorSet{
				{
					Entries: []kyvernov1.Attestor{
						{
							Keys: &kyvernov1.StaticKeyAttestor{
								PublicKeys: key,
							},
						},
					},
				},
			},
		}
	}

	ruleA, err := attestorCacheRule("verify-rule", withKey("KEY-A"))
	assert.NoError(t, err)
	ruleB, err := attestorCacheRule("verify-rule", withKey("KEY-B"))
	assert.NoError(t, err)
	assert.NotEqual(t, ruleA, ruleB, "same rule name with different key material must produce different cache rules")

	// Positive control: identical material must produce identical cache rule
	ruleARepeat, err := attestorCacheRule("verify-rule", withKey("KEY-A"))
	assert.NoError(t, err)
	assert.Equal(t, ruleA, ruleARepeat, "identical rule and key material must produce identical cache rule")

	// Different rule names with same material must produce different cache rules
	ruleDifferentName, err := attestorCacheRule("other-rule", withKey("KEY-A"))
	assert.NoError(t, err)
	assert.NotEqual(t, ruleA, ruleDifferentName, "different rule names must produce different cache rules")
}

func Test_hasUnbindableKeyMaterial(t *testing.T) {
	for _, tc := range []struct {
		name       string
		iv         *kyvernov1.ImageVerification
		unbindable bool
	}{
		{
			name: "inline public key",
			iv: &kyvernov1.ImageVerification{
				Attestors: []kyvernov1.AttestorSet{
					{
						Entries: []kyvernov1.Attestor{
							{
								Keys: &kyvernov1.StaticKeyAttestor{
									PublicKeys: "KEY-DATA",
								},
							},
						},
					},
				},
			},
			unbindable: false,
		},
		{
			name: "kms key in attestor",
			iv: &kyvernov1.ImageVerification{
				Attestors: []kyvernov1.AttestorSet{
					{
						Entries: []kyvernov1.Attestor{
							{
								Keys: &kyvernov1.StaticKeyAttestor{
									KMS: "awskms:///alias/signing",
								},
							},
						},
					},
				},
			},
			unbindable: true,
		},
		{
			name: "secret reference in attestor",
			iv: &kyvernov1.ImageVerification{
				Attestors: []kyvernov1.AttestorSet{
					{
						Entries: []kyvernov1.Attestor{
							{
								Keys: &kyvernov1.StaticKeyAttestor{
									Secret: &kyvernov1.SecretReference{
										Name:      "mysecret",
										Namespace: "default",
									},
								},
							},
						},
					},
				},
			},
			unbindable: true,
		},
		{
			name: "nested attestor with kms key",
			iv: &kyvernov1.ImageVerification{
				Attestors: []kyvernov1.AttestorSet{
					{
						Entries: []kyvernov1.Attestor{
							{
								Attestor: &apiextv1.JSON{
									Raw: []byte(`{"entries":[{"keys":{"kms":"awskms:///alias/nested"}}]}`),
								},
							},
						},
					},
				},
			},
			unbindable: true,
		},
		{
			name: "attestation with kms key",
			iv: &kyvernov1.ImageVerification{
				Attestations: []kyvernov1.Attestation{
					{
						PredicateType: "https://slsa.dev/provenance/v1",
						Attestors: []kyvernov1.AttestorSet{
							{
								Entries: []kyvernov1.Attestor{
									{
										Keys: &kyvernov1.StaticKeyAttestor{
											KMS: "gcpkms://...",
										},
									},
								},
							},
						},
					},
				},
			},
			unbindable: true,
		},
		{
			name: "keyless certificates",
			iv: &kyvernov1.ImageVerification{
				Attestors: []kyvernov1.AttestorSet{
					{
						Entries: []kyvernov1.Attestor{
							{
								Keyless: &kyvernov1.KeylessAttestor{
									Issuer:  "https://token.actions.githubusercontent.com",
									Subject: "https://github.com/kyverno/kyverno/.github/workflows/ci.yaml@refs/heads/main",
								},
							},
						},
					},
				},
			},
			unbindable: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.unbindable, hasUnbindableKeyMaterial(tc.iv))
		})
	}
}
