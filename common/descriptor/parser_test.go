package descriptor_test

import (
	"testing"

	"github.com/ark-network/ark/common"
	"github.com/ark-network/ark/common/descriptor"
	"github.com/stretchr/testify/require"
)

func TestParseTaprootDescriptor(t *testing.T) {
	t.Skip("Skipping test")
	tests := []struct {
		name     string
		desc     string
		expected descriptor.TaprootDescriptor
		wantErr  bool
	}{
		{
			name: "Basic Taproot",
			desc: "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)})",
			expected: descriptor.TaprootDescriptor{
				InternalKey: descriptor.Key{Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
				ScriptTree: []descriptor.Expression{
					&descriptor.PK{
						Key: descriptor.XOnlyKey{
							descriptor.Key{
								Hex: "81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "VTXO",
			desc: "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c),and(pk(59bffef74a89f39715b9f6b8a83e53a60a458d45542f20e2e2f4f7dbffafc5f8),older(144))})",
			expected: descriptor.TaprootDescriptor{
				InternalKey: descriptor.Key{Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
				ScriptTree: []descriptor.Expression{
					&descriptor.PK{
						Key: descriptor.XOnlyKey{
							descriptor.Key{
								Hex: "81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c",
							},
						},
					},
					&descriptor.And{
						First: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "59bffef74a89f39715b9f6b8a83e53a60a458d45542f20e2e2f4f7dbffafc5f8",
								},
							},
						},
						Second: &descriptor.Older{
							Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 144},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Boarding",
			desc: "tr(0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{ and(pk(973079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465), pk(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)), and(older(604672), pk(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)) })",
			expected: descriptor.TaprootDescriptor{
				InternalKey: descriptor.Key{Hex: "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"},
				ScriptTree: []descriptor.Expression{
					&descriptor.And{
						First: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "973079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
								},
							},
						},
						Second: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
								},
							},
						},
					},
					&descriptor.And{
						Second: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
								},
							},
						},
						First: &descriptor.Older{
							Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 604672},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:     "Invalid Key",
			desc:     "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798G,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)})",
			expected: descriptor.TaprootDescriptor{},
			wantErr:  true,
		},
		{
			name:     "Invalid Descriptor Format",
			desc:     "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
			expected: descriptor.TaprootDescriptor{},
			wantErr:  true,
		},
		{
			name:     "Invalid Descriptor Format - Missing Script Tree",
			desc:     "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
			expected: descriptor.TaprootDescriptor{},
			wantErr:  true,
		},
		{
			name: "Valid Empty Script Tree",
			desc: "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{})",
			expected: descriptor.TaprootDescriptor{
				InternalKey: descriptor.Key{Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
				ScriptTree:  []descriptor.Expression{},
			},
			wantErr: false,
		},
		{
			name: "Reversible VTXO",
			desc: "tr(0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,{ { and(pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465), pk(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)), and(older(604672), pk(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)) }, {and(pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465), pk(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))}})",
			expected: descriptor.TaprootDescriptor{
				InternalKey: descriptor.Key{Hex: "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"},
				ScriptTree: []descriptor.Expression{
					&descriptor.And{
						First: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
								},
							},
						},
						Second: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
								},
							},
						},
					},
					&descriptor.And{
						Second: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
								},
							},
						},
						First: &descriptor.Older{
							Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 604672},
						},
					},
					&descriptor.And{
						First: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
								},
							},
						},
						Second: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Multiple level descriptor",
			desc: `
			tr(
				0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,
				{
						{
								{
										and(and(pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465), pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465)), pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465)),
										and(older(512), and(pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465), pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465)))
								},
								{
										and(and(pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465), pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465)), pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465)),
										and(older(1024), and(pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465), pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465)))
								}
						},
						{
								and(older(512), pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465)),
								and(older(512), and(pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465), pk(873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465)))
						}
				}
			)
			`,
			expected: descriptor.TaprootDescriptor{
				InternalKey: descriptor.Key{Hex: "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"},
				ScriptTree: []descriptor.Expression{
					&descriptor.And{
						First: &descriptor.And{
							First: &descriptor.PK{
								Key: descriptor.XOnlyKey{
									descriptor.Key{
										Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
									},
								},
							},
							Second: &descriptor.PK{
								Key: descriptor.XOnlyKey{
									descriptor.Key{
										Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
									},
								},
							},
						},
						Second: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
								},
							},
						},
					},
					&descriptor.And{
						First: &descriptor.Older{
							Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 512},
						},
						Second: &descriptor.And{
							First: &descriptor.PK{
								Key: descriptor.XOnlyKey{
									descriptor.Key{
										Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
									},
								},
							},
							Second: &descriptor.PK{
								Key: descriptor.XOnlyKey{
									descriptor.Key{
										Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
									},
								},
							},
						},
					},
					&descriptor.And{
						First: &descriptor.And{
							First: &descriptor.PK{
								Key: descriptor.XOnlyKey{
									descriptor.Key{
										Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
									},
								},
							},
							Second: &descriptor.PK{
								Key: descriptor.XOnlyKey{
									descriptor.Key{
										Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
									},
								},
							},
						},
						Second: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
								},
							},
						},
					},
					&descriptor.And{
						First: &descriptor.Older{
							Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 1024},
						},
						Second: &descriptor.And{
							First: &descriptor.PK{
								Key: descriptor.XOnlyKey{
									descriptor.Key{
										Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
									},
								},
							},
							Second: &descriptor.PK{
								Key: descriptor.XOnlyKey{
									descriptor.Key{
										Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
									},
								},
							},
						},
					},
					&descriptor.And{
						First: &descriptor.Older{
							Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 512},
						},
						Second: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
								},
							},
						},
					},
					&descriptor.And{
						First: &descriptor.Older{
							Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 512},
						},
						Second: &descriptor.And{
							First: &descriptor.PK{
								Key: descriptor.XOnlyKey{
									descriptor.Key{
										Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
									},
								},
							},
							Second: &descriptor.PK{
								Key: descriptor.XOnlyKey{
									descriptor.Key{
										Hex: "873079a0091c9b16abd1f8c508320b07f0d50144d09ccd792ce9c915dac60465",
									},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := descriptor.ParseTaprootDescriptor(tt.desc)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
			require.Equal(t, tt.expected, *got)
		})
	}
}

func TestCompileDescriptor(t *testing.T) {
	t.Skip("Skipping test")
	tests := []struct {
		name     string
		desc     descriptor.TaprootDescriptor
		expected string
	}{
		{
			name: "Basic Taproot",
			desc: descriptor.TaprootDescriptor{
				InternalKey: descriptor.Key{Hex: descriptor.UnspendableKey},
				ScriptTree: []descriptor.Expression{
					&descriptor.PK{
						Key: descriptor.XOnlyKey{
							descriptor.Key{
								Hex: "81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c",
							},
						},
					},
				},
			},
			expected: "tr(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)})",
		},
		{
			name: "VTXO",
			desc: descriptor.TaprootDescriptor{
				InternalKey: descriptor.Key{Hex: descriptor.UnspendableKey},
				ScriptTree: []descriptor.Expression{
					&descriptor.PK{
						Key: descriptor.XOnlyKey{
							descriptor.Key{
								Hex: "81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c",
							},
						},
					},
					&descriptor.And{
						First: &descriptor.PK{
							Key: descriptor.XOnlyKey{
								descriptor.Key{
									Hex: "59bffef74a89f39715b9f6b8a83e53a60a458d45542f20e2e2f4f7dbffafc5f8",
								},
							},
						},
						Second: &descriptor.Older{
							Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 1024},
						},
					},
				},
			},
			expected: "tr(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c),and(pk(59bffef74a89f39715b9f6b8a83e53a60a458d45542f20e2e2f4f7dbffafc5f8),older(1024))})",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := descriptor.CompileDescriptor(tt.desc)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestParsePk(t *testing.T) {
	t.Skip("Skipping test")
	tests := []struct {
		policy         string
		expectedScript string
		expected       descriptor.PK
		verify         bool
	}{
		{
			policy:         "pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)",
			expectedScript: "2081e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952cac",
			verify:         false,
			expected: descriptor.PK{
				Key: descriptor.XOnlyKey{
					descriptor.Key{
						Hex: "81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c",
					},
				},
			},
		},
		{
			policy:         "pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c)",
			expectedScript: "2081e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952cad",
			verify:         true,
			expected: descriptor.PK{
				Key: descriptor.XOnlyKey{
					descriptor.Key{
						Hex: "81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c",
					},
				},
			},
		},
	}

	for _, test := range tests {
		var parsed descriptor.PK
		err := parsed.Parse(test.policy)
		require.NoError(t, err)
		require.Equal(t, test.expected, parsed)

		script, err := parsed.Script(test.verify)
		require.NoError(t, err)
		require.Equal(t, test.expectedScript, script)
	}
}

func TestParseOlder(t *testing.T) {
	t.Skip("Skipping test")
	tests := []struct {
		policy         string
		expectedScript string
		expected       descriptor.Older
	}{
		{
			policy:         "older(512)",
			expectedScript: "03010040b275",
			expected: descriptor.Older{
				Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 512},
			},
		},
		{
			policy:         "older(1024)",
			expectedScript: "03020040b275",
			expected: descriptor.Older{
				Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 1024},
			},
		},
	}

	for _, test := range tests {
		var parsed descriptor.Older
		err := parsed.Parse(test.policy)
		require.NoError(t, err)
		require.Equal(t, test.expected, parsed)

		script, err := parsed.Script(false)
		require.NoError(t, err)
		require.Equal(t, test.expectedScript, script)
	}
}

func TestParseAnd(t *testing.T) {
	t.Skip("Skipping test")
	tests := []struct {
		policy         string
		expectedScript string
		expected       descriptor.And
	}{
		{
			policy:         "and(pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c), older(512))",
			expectedScript: "2081e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952cad03010040b275",
			expected: descriptor.And{
				First: &descriptor.PK{
					Key: descriptor.XOnlyKey{
						descriptor.Key{
							Hex: "81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c",
						},
					},
				},
				Second: &descriptor.Older{
					Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 512},
				},
			},
		},
		{
			policy:         "and(older(512), pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c))",
			expectedScript: "03010040b2752081e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952cac",
			expected: descriptor.And{
				Second: &descriptor.PK{
					Key: descriptor.XOnlyKey{
						descriptor.Key{
							Hex: "81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c",
						},
					},
				},
				First: &descriptor.Older{
					Locktime: common.RelativeLocktime{Type: common.LocktimeTypeSecond, Value: 512},
				},
			},
		},
		{
			policy:         "and(pk(81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c), pk(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))",
			expectedScript: "2081e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952cad2079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
			expected: descriptor.And{
				First: &descriptor.PK{
					Key: descriptor.XOnlyKey{
						descriptor.Key{
							Hex: "81e0351fc94c3ba05f8d68354ff44711b02223f2b32fb7f3ef3a99a90af7952c",
						},
					},
				},
				Second: &descriptor.PK{
					Key: descriptor.XOnlyKey{
						descriptor.Key{
							Hex: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		var parsed descriptor.And
		err := parsed.Parse(test.policy)
		require.NoError(t, err)
		require.Equal(t, test.expected, parsed)

		script, err := parsed.Script(false)
		require.NoError(t, err)
		require.Equal(t, test.expectedScript, script)
	}
}
