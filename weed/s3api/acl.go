package s3api

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"github.com/chrislusf/seaweedfs/weed/glog"
	xhttp "github.com/chrislusf/seaweedfs/weed/s3api/http"
	"github.com/chrislusf/seaweedfs/weed/s3api/s3_constants"
	"github.com/chrislusf/seaweedfs/weed/s3api/s3err"
)

type ID string

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
	var grantees []Grant
	for _, grant := range acp_unmarshal.AccessControlList.Grant {
		grantees = append(grantees, Grant{
			Grantee: Grantee{
				XMLNS:       "http://www.w3.org/2001/XMLSchema-instance",
				XMLXSI:      grant.Grantee.XsiType,
				Type:        grant.Grantee.Type,
				ID:          grant.Grantee.ID,
				DisplayName: grant.Grantee.DisplayName,
			},
			Permission: grant.Permission,
		})
	}
	acp_marshal := AccessControlPolicyMarshal{
		XMLName: acp_unmarshal.XMLName,
		Owner:   acp_unmarshal.Owner,
		AccessControlList: AccessControlList{
			Grant: grantees,
		},
	}
	return acp_marshal
}

func (s3a *S3ApiServer) CreateACPolicyFromTemplate(id ID, display_name string, r *http.Request) (acPolicyRaw []byte, errCode s3err.ErrorCode) {
	newAclPolicy := AccessControlPolicyMarshal{
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
	newAclPolicy.Owner.ID = string(id)
	newAclPolicy.Owner.DisplayName = display_name
	newAclPolicy.AccessControlList.Grant[0].Grantee.ID = string(id)
	newAclPolicy.AccessControlList.Grant[0].Grantee.DisplayName = display_name

	return s3a.AddOwnerAndPermissionsFromHeaders(&newAclPolicy, r)
}

func UnmarshalAndCheckACL(acPolicyRaw []byte) (acPolicyMarshal *AccessControlPolicyMarshal, err error) {
	// Grants can be passed via headers, in that case request body is empty
	if len(acPolicyRaw) == 0 {
		return &AccessControlPolicyMarshal{}, nil
	}

	acPolicyUnmarshal := &AccessControlPolicyUnmarshal{}
	err = xml.Unmarshal(acPolicyRaw, acPolicyUnmarshal)
	if err != nil {
		return nil, fmt.Errorf("can't parse AC policy: %v", err)
	}

	// Check permissions
	for _, grant := range acPolicyUnmarshal.AccessControlList.Grant {
		ok := false
		for _, possiblePermission := range AclPermissions() {
			if grant.Permission == possiblePermission {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("permission %v is not allowed. allowed permissions are %v", grant.Permission, AclPermissions())
		}
	}

	acPolicy := acPolicyUnmarshal.ConvertToMarshal()

	return &acPolicy, nil
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

func (s3a *S3ApiServer) AddOwnerAndPermissionsFromHeaders(acPolicy *AccessControlPolicyMarshal, r *http.Request) (acPolicyRaw []byte, errCode s3err.ErrorCode) {
	if acPolicy.Owner.ID == "" {
		username, id, errCode := s3a.getUsernameAndId(r)
		if errCode != s3err.ErrNone {
			return nil, errCode
		}
		if acPolicy.Owner.DisplayName != "" && acPolicy.Owner.DisplayName != username {
			glog.V(3).Infof("Can't find user id by Display Name, because there is no IAM system")
			return nil, s3err.ErrMalformedACL
		}
		acPolicy.Owner.DisplayName = username
		acPolicy.Owner.ID = string(id)
	}

	for header, values := range r.Header {
		if strings.HasPrefix(header, xhttp.AmzGrantPrefix) {
			var permission Permission
			switch header {
			case xhttp.AmzGrantRead:
				permission = Permission("READ")
			case xhttp.AmzGrantReadACP:
				permission = Permission("READ_ACP")
			case xhttp.AmzGrantWrite:
				permission = Permission("WRITE")
			case xhttp.AmzGrantWriteACP:
				permission = Permission("WRITE_ACP")
			case xhttp.AmzGrantFullControl:
				permission = Permission("FULL_CONTROL")
			default:
				return nil, s3err.ErrInvalidRequest
			}
			for _, value := range values {
				granteeAndType := strings.Split(value, "=")
				if len(granteeAndType) != 2 {
					glog.V(3).Infof("Grantee header malformed: %s", value)
					return nil, s3err.ErrMalformedACL
				}
				granteeType, grantee := granteeAndType[0], granteeAndType[1]
				switch granteeType {
				case "uri":
					glog.V(3).Infof("Grantee can be specified only via id, because there is no IAM system")
					return nil, s3err.ErrMalformedACL
				case "email":
					glog.V(3).Infof("Grantee can be specified only via id, because there is no IAM system")
					return nil, s3err.ErrMalformedACL
				case "id":
					doesGrantExist := false
					for _, existingGrant := range acPolicy.AccessControlList.Grant {
						if existingGrant.Grantee.ID == grantee &&
							(existingGrant.Permission == permission || existingGrant.Permission == Permission("FULL_CONTROL")) {
							doesGrantExist = true
							break
						}
					}
					if !doesGrantExist {
						acPolicy.AccessControlList.Grant = append(acPolicy.AccessControlList.Grant, Grant{
							Grantee: Grantee{
								XMLNS:  "http://www.w3.org/2001/XMLSchema-instance",
								XMLXSI: "CanonicalUser",
								Type:   "CanonicalUser",
								ID:     grantee,
							},
							Permission: permission,
						})
					}
				default:
					glog.V(3).Infof("Grantee header malformed: %s", value)
					return nil, s3err.ErrMalformedACL
				}
			}
		}
	}
	acPolicyRaw, err := xml.Marshal(acPolicy)
	if err != nil {
		glog.Errorf("Can't marshal policy after adding owner and permissions from headers: %v", err)
		return nil, s3err.ErrMalformedACL
	}

	return acPolicyRaw, s3err.ErrNone
}

func AclMapBucket(permission Permission) []Action {
	switch permission {
	case "READ":
		return []Action{"ListBucket", "ListBucketVersions", "ListBucketMultipartUploads", "GetObject", "GetObjectVersion"}
	case "WRITE":
		return []Action{"PutObject", "DeleteObjectVersion", "CopyObject", "DeleteObject",
			"CopyObjectPart", "PutObjectPart", "CompleteMultipartUpload", "NewMultipartUpload", "AbortMultipartUpload"}
	case "READ_ACP":
		return []Action{"GetBucketAcl", "GetObjectAcl", "GetObjectVersionAcl"}
	case "WRITE_ACP":
		return []Action{"PutBucketAcl", "PutObjectAcl", "PutObjectVersionAcl"}
	case "FULL_CONTROL":
		return []Action{"ListBucket", "ListBucketVersions", "ListBucketMultipartUploads", "GetObject", "GetObjectVersion",
			"PutObject", "DeleteObjectVersion", "CopyObject", "DeleteObject",
			"CopyObjectPart", "PutObjectPart", "CompleteMultipartUpload", "NewMultipartUpload", "AbortMultipartUpload",
			"GetBucketAcl", "GetObjectAcl", "GetObjectVersionAcl", "PutBucketAcl", "PutObjectAcl",
			"PutObjectVersionAcl"}
	default:
		return nil
	}
}

func AclMapObject(permission Permission) []Action {
	switch permission {
	case "READ":
		return []Action{"GetObject", "GetObjectVersion", "HeadObject", "ListObjectParts", "ListMultipartUploads"}
	case "READ_ACP":
		return []Action{"GetBucketAcl", "GetObjectAcl", "GetObjectVersionAcl"}
	case "WRITE_ACP":
		return []Action{"PutObjectAcl", "PutObjectVersionAcl"}
	case "FULL_CONTROL":
		return []Action{"GetObject", "GetObjectVersion", "HeadObject", "ListObjectParts", "ListMultipartUploads",
			"GetObjectAcl", "GetObjectVersionAcl", "PutObjectAcl",
			"PutObjectVersionAcl"}
	default:
		return nil
	}
}

func AclPermissions() []Permission {
	return []Permission{"READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"}
}

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
		for _, allowed_action := range AclMapBucket(permission) {
			if action == allowed_action {
				return true
			}
		}
	}

	permissions_object := ac_policy_object.findUserRights(*id)
	for _, permission := range permissions_object {
		for _, allowed_action := range AclMapObject(permission) {
			if action == allowed_action {
				return true
			}
		}
	}

	return false
}
