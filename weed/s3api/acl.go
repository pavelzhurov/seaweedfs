package s3api

import "encoding/xml"

type AccessControlPolicyTemplate = AccessControlPolicyMarshal

// Generated XML structures are not compatible with some AWS default attributes, so we need to redefine some of them.

// First, when marshaling structures to XML we need to add xmlns attribute. It can be done via extra XMLName field.
type AccessControlPolicyMarshal struct {
	XMLName           xml.Name          `xml:"http://s3.amazonaws.com/doc/2006-03-01/ AccessControlPolicy"`
	Owner             CanonicalUser     `xml:"Owner"`
	AccessControlList AccessControlList `xml:"AccessControlList"`
}

// While marshaling works pretty well with generated structures, unmarshaling doesn't preserve attributes.
// So, we create slightly different version of generated structures specially for unmarshaling XML.
type AccessControlListUnmarshal struct {
	Grant []GrantUnmarshal `xml:"Grant,omitempty"`
}

type AccessControlPolicyUnmarshal struct {
	XMLName           xml.Name                   `xml:"http://s3.amazonaws.com/doc/2006-03-01/ AccessControlPolicy"`
	Owner             CanonicalUser              `xml:"Owner"`
	AccessControlList AccessControlListUnmarshal `xml:"AccessControlList"`
}

type GrantUnmarshal struct {
	Grantee    GranteeUnmarshal `xml:"Grantee"`
	Permission Permission       `xml:"Permission"`
}

type GranteeUnmarshal struct {
	XMLName     xml.Name `xml:"Grantee"`
	XsiType     string   `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Type        string   `xml:"Type"`
	ID          string   `xml:"ID,omitempty"`
	DisplayName string   `xml:"DisplayName,omitempty"`
	URI         string   `xml:"URI,omitempty"`
}

// Also, we need a function which will convert Unmarshal structures to Marshal ones.
func (acp_unmarshal *AccessControlPolicyUnmarshal) ConvertToMarshal() AccessControlPolicyMarshal {
	acp_marshal := AccessControlPolicyMarshal{
		XMLName: acp_unmarshal.XMLName,
		Owner:   acp_unmarshal.Owner,
		AccessControlList: AccessControlList{
			Grant: []Grant{
				{
					Grantee: Grantee{
						XMLNS:       "http://www.w3.org/2001/XMLSchema-instance",
						XMLXSI:      acp_unmarshal.AccessControlList.Grant[0].Grantee.XsiType,
						Type:        acp_unmarshal.AccessControlList.Grant[0].Grantee.Type,
						ID:          acp_unmarshal.AccessControlList.Grant[0].Grantee.ID,
						DisplayName: acp_unmarshal.AccessControlList.Grant[0].Grantee.DisplayName,
					},
					Permission: acp_unmarshal.AccessControlList.Grant[0].Permission,
				},
			},
		},
	}
	return acp_marshal
}

func (acpt *AccessControlPolicyTemplate) CreateACPolicyFromTemplate(id string, display_name string) AccessControlPolicyMarshal {
	new_acl_policy := *acpt
	new_acl_policy.Owner.ID = id
	new_acl_policy.Owner.DisplayName = display_name
	new_acl_policy.AccessControlList.Grant[0].Grantee.ID = id
	new_acl_policy.AccessControlList.Grant[0].Grantee.DisplayName = display_name
	return new_acl_policy
}

var defaultACPolicyTemplate *AccessControlPolicyTemplate = &AccessControlPolicyTemplate{
	XMLName: xml.Name{
		Space: "http://s3.amazonaws.com/doc/2006-03-01/",
		Local: "AccessControlPolicy",
	},
	Owner: CanonicalUser{
		ID:          "",
		DisplayName: "",
	},
	AccessControlList: AccessControlList{
		Grant: []Grant{
			{
				Grantee: Grantee{
					XMLNS:       "http://www.w3.org/2001/XMLSchema-instance",
					XMLXSI:      "CanonicalUser",
					Type:        "CanonicalUser",
					ID:          "",
					DisplayName: "",
				},
				Permission: "FULL_CONTROL",
			},
		},
	},
}
