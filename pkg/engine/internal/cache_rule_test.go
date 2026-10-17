package internal

import (
	"testing"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/pkg/config"
	enginecontext "github.com/kyverno/kyverno/pkg/engine/context"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
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
									PublicKeys: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----",
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
		{
			name: "k8s secret in publicKeys",
			iv: &kyvernov1.ImageVerification{
				Attestors: []kyvernov1.AttestorSet{
					{
						Entries: []kyvernov1.Attestor{
							{
								Keys: &kyvernov1.StaticKeyAttestor{
									PublicKeys: "k8s://default/mysecret",
								},
							},
						},
					},
				},
			},
			unbindable: true,
		},
		{
			name: "nested attestor with k8s secret in publicKeys",
			iv: &kyvernov1.ImageVerification{
				Attestors: []kyvernov1.AttestorSet{
					{
						Entries: []kyvernov1.Attestor{
							{
								Attestor: &apiextv1.JSON{
									Raw: []byte(`{"entries":[{"keys":{"publicKeys":"k8s://default/nested-secret"}}]}`),
								},
							},
						},
					},
				},
			},
			unbindable: true,
		},
		{
			name: "attestation with k8s secret in publicKeys",
			iv: &kyvernov1.ImageVerification{
				Attestations: []kyvernov1.Attestation{
					{
						PredicateType: "https://slsa.dev/provenance/v1",
						Attestors: []kyvernov1.AttestorSet{
							{
								Entries: []kyvernov1.Attestor{
									{
										Keys: &kyvernov1.StaticKeyAttestor{
											PublicKeys: "k8s://default/att-secret",
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
			name: "attestation condition with k8s reference",
			iv: &kyvernov1.ImageVerification{
				Attestations: []kyvernov1.Attestation{
					{
						PredicateType: "https://slsa.dev/provenance/v1",
						Conditions: []kyvernov1.AnyAllConditions{
							{
								AllConditions: []kyvernov1.Condition{
									{
										RawKey:   &apiextv1.JSON{Raw: []byte(`"k8s://default/secret"`)},
										Operator: "Equals",
										RawValue: &apiextv1.JSON{Raw: []byte(`"val"`)},
									},
								},
							},
						},
					},
				},
			},
			unbindable: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.unbindable, hasUnbindableKeyMaterial(tc.iv))
		})
	}
}

func Test_attestorCacheRule_BindsConditionVariables(t *testing.T) {
	jp := jmespath.New(config.NewDefaultConfiguration(false))
	newCtx := func(builder string) enginecontext.Interface {
		ctx := enginecontext.NewContext(jp)
		_ = ctx.AddVariable("cm.data.builder", builder)
		return ctx
	}

	iv := &kyvernov1.ImageVerification{
		Attestations: []kyvernov1.Attestation{
			{
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Conditions: []kyvernov1.AnyAllConditions{
					{
						AllConditions: []kyvernov1.Condition{
							{
								RawKey:   &apiextv1.JSON{Raw: []byte(`"{{ builder.id }}"`)},
								Operator: "Equals",
								RawValue: &apiextv1.JSON{Raw: []byte(`"{{ cm.data.builder }}"`)},
							},
						},
					},
				},
			},
		},
	}

	ruleA, err := attestorCacheRule("verify-rule", iv, newCtx("builder-A"))
	assert.NoError(t, err)

	ruleB, err := attestorCacheRule("verify-rule", iv, newCtx("builder-B"))
	assert.NoError(t, err)

	assert.NotEqual(t, ruleA, ruleB, "rotating ConfigMap value in condition must change cache rule")

	ruleARepeat, err := attestorCacheRule("verify-rule", iv, newCtx("builder-A"))
	assert.NoError(t, err)
	assert.Equal(t, ruleA, ruleARepeat, "identical condition variable value must produce identical cache rule")
}

func Test_hasDynamicAuthority(t *testing.T) {
	staticIV := &kyvernov1.ImageVerification{
		Attestors: []kyvernov1.AttestorSet{
			{
				Entries: []kyvernov1.Attestor{
					{
						Keys: &kyvernov1.StaticKeyAttestor{
							PublicKeys: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----",
						},
					},
				},
			},
		},
	}

	// 1. Static rule with static key material -> false (fast path eligible)
	staticRule := &kyvernov1.Rule{
		Name: "static-rule",
	}
	assert.False(t, hasDynamicAuthority(staticRule, staticIV))

	// 2. Rule with context entries (e.g. ConfigMap) -> true (fast path bypassed)
	contextRule := &kyvernov1.Rule{
		Name: "cm-rule",
		Context: []kyvernov1.ContextEntry{
			{
				Name: "attestorkeys",
			},
		},
	}
	assert.True(t, hasDynamicAuthority(contextRule, staticIV))

	// 3. Rule with variable in verification -> true (fast path bypassed)
	varRule := &kyvernov1.Rule{
		Name: "var-rule",
	}
	varIV := &kyvernov1.ImageVerification{
		Attestors: []kyvernov1.AttestorSet{
			{
				Entries: []kyvernov1.Attestor{
					{
						Keys: &kyvernov1.StaticKeyAttestor{
							PublicKeys: "{{ attestorkeys.data.key }}",
						},
					},
				},
			},
		},
	}
	assert.True(t, hasDynamicAuthority(varRule, varIV))

	// 4. Rule with unbindable KMS or Secret -> true (fast path bypassed)
	kmsIV := &kyvernov1.ImageVerification{
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
	}
	assert.True(t, hasDynamicAuthority(staticRule, kmsIV))

	k8sSecretIV := &kyvernov1.ImageVerification{
		Attestors: []kyvernov1.AttestorSet{
			{
				Entries: []kyvernov1.Attestor{
					{
						Keys: &kyvernov1.StaticKeyAttestor{
							PublicKeys: "k8s://default/mysecret",
						},
					},
				},
			},
		},
	}
	assert.True(t, hasDynamicAuthority(staticRule, k8sSecretIV))
}
