// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

type CapabilityInterface interface {
	TLVInterface
	CapStrings() []string
}

func PolaCapability(caps []CapabilityInterface) []CapabilityInterface {
	polaCaps := []CapabilityInterface{}
	for _, cap := range caps {
		switch tlv := cap.(type) {
		case *StatefulPCECapability:
			tlv = &StatefulPCECapability{
				LSPUpdateCapability:            true,
				IncludeDBVersion:               false,
				LSPInstantiationCapability:     true,
				TriggeredResync:                false,
				DeltaLSPSyncCapability:         false,
				TriggeredInitialSync:           false,
				P2mpCapability:                 false,
				P2mpLSPUpdateCapability:        false,
				P2mpLSPInstantiationCapability: false,
				LSPSchedulingCapability:        false,
				PdLSPCapability:                false,
				ColorCapability:                true,
				PathRecomputationCapability:    false,
				StrictPathCapability:           false,
				Relax:                          false,
			}
			polaCaps = append(polaCaps, tlv)
		case *LSPDBVersion:
			continue
		case *HPCECapability:
			continue
		case *DomainID:
			continue
		default:
			polaCaps = append(polaCaps, tlv)
		}
	}
	return polaCaps
}

func PolaPCEPClientCapability() []CapabilityInterface {
	return []CapabilityInterface{
		// Basic stateful PCE capabilities for Child PCE
		&StatefulPCECapability{
			LSPUpdateCapability:            true,
			IncludeDBVersion:               false,
			LSPInstantiationCapability:     true,
			TriggeredResync:                false,
			DeltaLSPSyncCapability:         false,
			TriggeredInitialSync:           false,
			P2mpCapability:                 false,
			P2mpLSPUpdateCapability:        false,
			P2mpLSPInstantiationCapability: false,
			LSPSchedulingCapability:        false,
			PdLSPCapability:                false,
			ColorCapability:                true,
			PathRecomputationCapability:    false, // Standard for Child PCE
			StrictPathCapability:           false,
			Relax:                          false,
		},
		// Path Setup Type Capability for SRv6 support
		&PathSetupTypeCapability{
			PathSetupTypes: []Pst{PathSetupTypeSRv6TE},
			SubTLVs:        []TLVInterface{},
		},
		// Association Type List for SR Policy
		&AssocTypeList{
			AssocTypes: []AssocType{AssocTypeSRPolicyAssociation},
		},
	}
}
