package s3api

import (
	"encoding/xml"
	"net/http"

	xhttp "github.com/chrislusf/seaweedfs/weed/s3api/http"
	"github.com/chrislusf/seaweedfs/weed/s3api/s3_constants"
	"github.com/chrislusf/seaweedfs/weed/s3api/s3err"
)

type ID string

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

func (acpt *AccessControlPolicyTemplate) CreateACPolicyFromTemplate(id ID, display_name string) AccessControlPolicyMarshal {
	new_acl_policy := *acpt
	new_acl_policy.Owner.ID = string(id)
	new_acl_policy.Owner.DisplayName = display_name
	new_acl_policy.AccessControlList.Grant[0].Grantee.ID = string(id)
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

func (s3a *S3ApiServer) getUsernameAndId(request *http.Request) (username string, id ID, errCode s3err.ErrorCode) {
	if s3a.iam.isEnabled() {
		if ident, errCode := s3a.iam.authRequest(request, s3_constants.ACTION_ADMIN, s3a); errCode != s3err.ErrNone {
			return "", "", errCode
		} else {
			username = ident.Name
		}
	}

	if identityId := request.Header.Get(xhttp.AmzIdentityId); identityId != "" {
		if username == "" {
			username = identityId
		}
		id = ID(identityId)
	} else {
		// TODO: Anonymous handling could be revised in accordance with public caned policies
		if username == "" {
			username = "anonymous"
			id = ID("anonymous")
		}
		if id == "" {
			id = ID(username)
		}
	}
	return username, id, s3err.ErrNone
}

var ACL_MAP_BUCKET = map[Permission][]Action{
	"READ":      {"ListBucket", "ListBucketVersions", "ListBucketMultipartUploads", "GetObject", "GetObjectVersion"},
	"WRITE":     {"PutObject", "DeleteObjectVersion", "CopyObject", "DeleteObject"},
	"READ_ACP":  {"GetBucketAcl", "GetObjectAcl", "GetObjectVersionAcl"},
	"WRITE_ACP": {"PutBucketAcl", "PutObjectAcl", "PutObjectVersionAcl"},
	"FULL_CONTROL": {"ListBucket", "ListBucketVersions", "ListBucketMultipartUploads", "GetObject", "GetObjectVersion",
		"PutObject", "DeleteObjectVersion", "CopyObject", "DeleteObject",
		"GetBucketAcl", "GetObjectAcl", "GetObjectVersionAcl", "PutBucketAcl", "PutObjectAcl",
		"PutObjectVersionAcl"},
}

var ACL_MAP_OBJECT = map[Permission][]Action{
	"READ":      {"GetObject", "GetObjectVersion"},
	"READ_ACP":  {"GetObjectAcl", "GetObjectVersionAcl"},
	"WRITE_ACP": {"PutObjectAcl", "PutObjectVersionAcl"},
	"FULL_CONTROL": {"GetObject", "GetObjectVersion",
		"GetObjectAcl", "GetObjectVersionAcl", "PutObjectAcl",
		"PutObjectVersionAcl"},
}

var ACL_PERMISSIONS = []Permission{"READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"}

func (ac_policy AccessControlPolicyMarshal) findUserRights(id ID) []Permission {
	var user_rights []Permission
	for _, grant := range ac_policy.AccessControlList.Grant {
		if grant.Grantee.ID == string(id) {
			if grant.Permission == Permission("FULL_CONTROL") {
				return []Permission{"FULL_CONTROL"}
			} else {
				user_rights = append(user_rights, grant.Permission)
			}
		}
	}
	return user_rights
}

func (id *ID) authzAcl(action Action, ac_policy_object AccessControlPolicyMarshal, ac_policy_bucket AccessControlPolicyMarshal) bool {
	permissions_bucket := ac_policy_bucket.findUserRights(*id)
	for _, permission := range permissions_bucket {
		for _, allowed_action := range ACL_MAP_BUCKET[permission] {
			if action == allowed_action {
				return true
			}
		}
	}

	permissions_object := ac_policy_object.findUserRights(*id)
	for _, permission := range permissions_object {
		for _, allowed_action := range ACL_MAP_OBJECT[permission] {
			if action == allowed_action {
				return true
			}
		}
	}

	return false
}
