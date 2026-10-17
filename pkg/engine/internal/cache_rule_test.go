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
	assert.Equal(t, "{{ builder.id }}", substituteContextVariablesInString("{{ builder.id }}", newCtx("builder-A")))
}

func Test_attestorCacheRule_BindsDenyConditionVariables(t *testing.T) {
	jp := jmespath.New(config.NewDefaultConfiguration(false))
	ctx := enginecontext.NewContext(jp)
	_ = ctx.AddVariable("cm.data.allowed", "A")

	iv := &kyvernov1.ImageVerification{
		Validation: kyvernov1.ValidateImageVerification{
			Deny: &kyvernov1.Deny{},
		},
	}
	iv.Validation.Deny.SetAnyAllConditions(map[string]interface{}{
		"all": []interface{}{map[string]interface{}{
			"key": "{{ cm.data.allowed }}", "operator": "Equals", "value": "x",
		}},
	})

	ruleA, err := attestorCacheRule("verify-rule", iv, ctx)
	assert.NoError(t, err)

	rotated := enginecontext.NewContext(jp)
	_ = rotated.AddVariable("cm.data.allowed", "B")
	ruleB, err := attestorCacheRule("verify-rule", iv, rotated)
	assert.NoError(t, err)
	assert.NotEqual(t, ruleA, ruleB, "rotating ConfigMap in deny conditions must produce different cache rule")
}

func Test_attestorCacheRule_PreservesConditionType(t *testing.T) {
	jp := jmespath.New(config.NewDefaultConfiguration(false))
	ctxNum := enginecontext.NewContext(jp)
	_ = ctxNum.AddVariable("cm.data.val", 1)

	ctxStr := enginecontext.NewContext(jp)
	_ = ctxStr.AddVariable("cm.data.val", "1")

	iv := &kyvernov1.ImageVerification{
		Attestations: []kyvernov1.Attestation{
			{
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Conditions: []kyvernov1.AnyAllConditions{
					{
						AllConditions: []kyvernov1.Condition{
							{
								RawKey:   &apiextv1.JSON{Raw: []byte(`"{{ predicate.val }}"`)},
								Operator: "Equals",
								RawValue: &apiextv1.JSON{Raw: []byte(`"{{ cm.data.val }}"`)},
							},
						},
					},
				},
			},
		},
	}

	ruleNum, err := attestorCacheRule("verify-rule", iv, ctxNum)
	assert.NoError(t, err)

	ruleStr, err := attestorCacheRule("verify-rule", iv, ctxStr)
	assert.NoError(t, err)

	assert.NotEqual(t, ruleNum, ruleStr, "numeric 1 and string '1' must produce distinct cache rules")
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
	assert.False(t, hasDynamicAuthority(staticRule, staticRule, staticIV))

	// 2. Rule with context entries (e.g. ConfigMap) in pre-substitution rule -> true (fast path bypassed)
	contextRule := &kyvernov1.Rule{
		Name: "cm-rule",
		Context: []kyvernov1.ContextEntry{
			{
				Name: "attestorkeys",
			},
		},
	}
	assert.True(t, hasDynamicAuthority(contextRule, staticRule, staticIV))

	// 3. Pre-substitution rule with variable in verification -> true (fast path bypassed even after substitution)
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
	assert.True(t, hasDynamicAuthority(varRule, staticRule, varIV))

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
	assert.True(t, hasDynamicAuthority(staticRule, staticRule, kmsIV))

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
	assert.True(t, hasDynamicAuthority(staticRule, staticRule, k8sSecretIV))

	// 5. Attestation with unresolvable condition variables -> true (fast path bypassed)
	unresolvedCondIV := &kyvernov1.ImageVerification{
		Attestations: []kyvernov1.Attestation{
			{
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Conditions: []kyvernov1.AnyAllConditions{
					{
						AllConditions: []kyvernov1.Condition{
							{
								RawKey:   &apiextv1.JSON{Raw: []byte(`"{{ builder.id }}"`)},
								Operator: "Equals",
								RawValue: &apiextv1.JSON{Raw: []byte(`"builder-A"`)},
							},
						},
					},
				},
			},
		},
	}
	assert.True(t, hasDynamicAuthority(staticRule, staticRule, unresolvedCondIV))
}

func Test_hasUnresolvedConditionVariables(t *testing.T) {
	jp := jmespath.New(config.NewDefaultConfiguration(false))
	ctx := enginecontext.NewContext(jp)
	_ = ctx.AddVariable("cm.data.builder", "builder-A")

	// 1. Condition with unresolvable statement variable -> true
	unresolvedIV := &kyvernov1.ImageVerification{
		Attestations: []kyvernov1.Attestation{
			{
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Conditions: []kyvernov1.AnyAllConditions{
					{
						AllConditions: []kyvernov1.Condition{
							{
								RawKey:   &apiextv1.JSON{Raw: []byte(`"{{ builder.id }}"`)},
								Operator: "Equals",
								RawValue: &apiextv1.JSON{Raw: []byte(`"builder-A"`)},
							},
						},
					},
				},
			},
		},
	}
	assert.True(t, hasUnresolvedConditionVariables(unresolvedIV, ctx))

	// 2. Condition with all variables resolved by context -> false
	resolvedIV := &kyvernov1.ImageVerification{
		Attestations: []kyvernov1.Attestation{
			{
				PredicateType: "https://slsa.dev/provenance/v0.2",
				Conditions: []kyvernov1.AnyAllConditions{
					{
						AllConditions: []kyvernov1.Condition{
							{
								RawKey:   &apiextv1.JSON{Raw: []byte(`"{{ cm.data.builder }}"`)},
								Operator: "Equals",
								RawValue: &apiextv1.JSON{Raw: []byte(`"builder-A"`)},
							},
						},
					},
				},
			},
		},
	}
	assert.False(t, hasUnresolvedConditionVariables(resolvedIV, ctx))

	// 3. Attestation with no conditions -> false
	noCondIV := &kyvernov1.ImageVerification{
		Attestations: []kyvernov1.Attestation{
			{
				PredicateType: "https://slsa.dev/provenance/v0.2",
			},
		},
	}
	assert.False(t, hasUnresolvedConditionVariables(noCondIV, ctx))

	// 4. Deny condition with unresolvable variable -> true
	denyIV := &kyvernov1.ImageVerification{
		Validation: kyvernov1.ValidateImageVerification{
			Deny: &kyvernov1.Deny{},
		},
	}
	denyIV.Validation.Deny.SetAnyAllConditions(map[string]interface{}{
		"all": []interface{}{map[string]interface{}{
			"key": "{{ scan.critical }}", "operator": "GreaterThan", "value": 0,
		}},
	})
	assert.True(t, hasUnresolvedConditionVariables(denyIV, ctx))
}
