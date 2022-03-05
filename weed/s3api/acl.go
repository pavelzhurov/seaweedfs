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

// Hardcode groups, because there is no IAM system
const (
	AllUsersGroup           = "http://acs.amazonaws.com/groups/global/AllUsers"
	AuthenticatedUsersGroup = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

	UserType  = "CanonicalUser"
	GroupType = "Group"

	PermissionRead        = Permission("READ")
	PermissionWrite       = Permission("WRITE")
	PermissionReadACP     = Permission("READ_ACP")
	PermissionWriteACP    = Permission("WRITE_ACP")
	PermissionFullControl = Permission("FULL_CONTROL")

	// Virtual Group for Canned ACL
	BucketOwnerGroup = "http://example.com/BucketOwner"
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
				URI:         grant.Grantee.URI,
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

func (s3a *S3ApiServer) CreateACPolicyFromTemplate(id ID, display_name string, r *http.Request, isObject bool) (acPolicyRaw []byte, errCode s3err.ErrorCode) {
	newAclPolicy := AccessControlPolicyMarshal{
		XMLName: xml.Name{
			Space: "http://s3.amazonaws.com/doc/2006-03-01/",
			Local: "AccessControlPolicy",
		},
		Owner: CanonicalUser{
			ID:          string(id),
			DisplayName: display_name,
		},
		AccessControlList: AccessControlList{
			Grant: []Grant{
				{
					Grantee: Grantee{
						XMLNS:       "http://www.w3.org/2001/XMLSchema-instance",
						XMLXSI:      UserType,
						Type:        UserType,
						ID:          string(id),
						DisplayName: display_name,
					},
					Permission: "FULL_CONTROL",
				},
			},
		},
	}

	return s3a.AddOwnerAndPermissionsFromHeaders(&newAclPolicy, r, isObject, string(id))
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
		if grant.Grantee.ID == "" &&
			!(grant.Grantee.URI == AllUsersGroup || grant.Grantee.URI == AuthenticatedUsersGroup) {
			return nil, fmt.Errorf("grantee ID can't be empty, while URI (%v) doesn't represent valid group one of the (%v, %v)",
				grant.Grantee.URI, AllUsersGroup, AuthenticatedUsersGroup)
		}

		if !(grant.Grantee.XsiType == UserType || grant.Grantee.XsiType == GroupType) {
			return nil, fmt.Errorf("invalid grantee type %v, valid grantee types are %v, %v",
				grant.Grantee.Type, UserType, GroupType)
		}

		if grant.Grantee.Type == "" {
			grant.Grantee.Type = grant.Grantee.XsiType
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

func (acPolicy *AccessControlPolicyMarshal) addGroupGrant(grantee string, permission Permission) (errCode s3err.ErrorCode) {
	if !(grantee == AuthenticatedUsersGroup || grantee == AllUsersGroup || grantee == BucketOwnerGroup) {
		glog.V(3).Infof("Grantee can be specified only via id, because there is no IAM system")
		return s3err.ErrMalformedACL
	}
	// Since we can specified only AllUsersGroup and AuthenticatedUsersGroup via URI,
	// the only possible type is GroupType
	doesGrantExist := false
	for _, existingGrant := range acPolicy.AccessControlList.Grant {
		if existingGrant.Grantee.URI == grantee &&
			(existingGrant.Permission == permission || existingGrant.Permission == PermissionFullControl) {
			doesGrantExist = true
			break
		}
	}
	if !doesGrantExist {
		acPolicy.AccessControlList.Grant = append(acPolicy.AccessControlList.Grant, Grant{
			Grantee: Grantee{
				XMLNS:  "http://www.w3.org/2001/XMLSchema-instance",
				XMLXSI: GroupType,
				Type:   GroupType,
				URI:    grantee,
			},
			Permission: permission,
		})
	}

	return s3err.ErrNone
}

func (acPolicy *AccessControlPolicyMarshal) addUserGrant(grantee string, permission Permission) (errCode s3err.ErrorCode) {
	doesGrantExist := false
	for _, existingGrant := range acPolicy.AccessControlList.Grant {
		if existingGrant.Grantee.ID == grantee &&
			(existingGrant.Permission == permission || existingGrant.Permission == PermissionFullControl) {
			doesGrantExist = true
			break
		}
	}
	if !doesGrantExist {
		acPolicy.AccessControlList.Grant = append(acPolicy.AccessControlList.Grant, Grant{
			Grantee: Grantee{
				XMLNS:  "http://www.w3.org/2001/XMLSchema-instance",
				XMLXSI: UserType,
				Type:   UserType,
				ID:     grantee,
			},
			Permission: permission,
		})
	}

	return s3err.ErrNone
}

func (s3a *S3ApiServer) AddOwnerAndPermissionsFromHeaders(acPolicy *AccessControlPolicyMarshal, r *http.Request, isObject bool, owner string) (acPolicyRaw []byte, errCode s3err.ErrorCode) {
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
				permission = PermissionRead
			case xhttp.AmzGrantReadACP:
				permission = PermissionReadACP
			case xhttp.AmzGrantWrite:
				permission = PermissionWrite
			case xhttp.AmzGrantWriteACP:
				permission = PermissionWriteACP
			case xhttp.AmzGrantFullControl:
				permission = PermissionFullControl
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
					errCode := acPolicy.addGroupGrant(grantee, permission)
					if errCode != s3err.ErrNone {
						return nil, errCode
					}
				case "email":
					glog.V(3).Infof("Grantee can be specified only via id, because there is no IAM system")
					return nil, s3err.ErrMalformedACL
				case "id":
					errCode := acPolicy.addUserGrant(grantee, permission)
					if errCode != s3err.ErrNone {
						return nil, errCode
					}
				default:
					glog.V(3).Infof("Grantee header malformed: %s", value)
					return nil, s3err.ErrMalformedACL
				}
			}
		} else if header == xhttp.AmzACL {
			if len(values) > 1 {
				return nil, s3err.ErrInvalidRequest
			}
			switch values[0] {
			case "private":
				errCode := acPolicy.addUserGrant(owner, PermissionFullControl)
				if errCode != s3err.ErrNone {
					return nil, errCode
				}
			case "public-read":
				errCode := acPolicy.addUserGrant(owner, PermissionFullControl)
				if errCode != s3err.ErrNone {
					return nil, errCode
				}
				errCode = acPolicy.addGroupGrant(AllUsersGroup, PermissionRead)
				if errCode != s3err.ErrNone {
					return nil, errCode
				}
			case "public-read-write":
				errCode := acPolicy.addUserGrant(owner, PermissionFullControl)
				if errCode != s3err.ErrNone {
					return nil, errCode
				}
				errCode = acPolicy.addGroupGrant(AllUsersGroup, PermissionRead)
				if errCode != s3err.ErrNone {
					return nil, errCode
				}
				errCode = acPolicy.addGroupGrant(AllUsersGroup, PermissionWrite)
				if errCode != s3err.ErrNone {
					return nil, errCode
				}
			case "aws-exec-read":
				return nil, s3err.ErrNotImplemented
			case "authenticated-read":
				errCode = acPolicy.addUserGrant(owner, PermissionFullControl)
				if errCode != s3err.ErrNone {
					return nil, errCode
				}
				errCode := acPolicy.addGroupGrant(AuthenticatedUsersGroup, PermissionRead)
				if errCode != s3err.ErrNone {
					return nil, errCode
				}
			case "bucket-owner-read":
				if !isObject {
					return nil, s3err.ErrMalformedACL
				}
				errCode := acPolicy.addUserGrant(owner, PermissionFullControl)
				if errCode != s3err.ErrNone {
					return nil, errCode
				}
				errCode = acPolicy.addGroupGrant(BucketOwnerGroup, PermissionRead)
				if errCode != s3err.ErrNone {
					return nil, errCode
				}
			case "bucket-owner-full-control":
				if !isObject {
					return nil, s3err.ErrMalformedACL
				}
				errCode := acPolicy.addUserGrant(owner, PermissionFullControl)
				if errCode != s3err.ErrNone {
					return nil, errCode
				}
				errCode = acPolicy.addGroupGrant(BucketOwnerGroup, PermissionFullControl)
				if errCode != s3err.ErrNone {
					return nil, errCode
				}
			default:
				return nil, s3err.ErrInvalidRequest
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
		return []Action{"ListBucket", "ListBucketVersions", "ListBucketMultipartUploads"}
	case "WRITE":
		return []Action{"PutObject", "DeleteObjectVersion", "CopyObject", "DeleteObject",
			"CopyObjectPart", "PutObjectPart", "CompleteMultipartUpload", "NewMultipartUpload", "AbortMultipartUpload"}
	case "READ_ACP":
		return []Action{"GetBucketAcl"}
	case "WRITE_ACP":
		return []Action{"PutBucketAcl"}
	case "FULL_CONTROL":
		return []Action{"ListBucket", "ListBucketVersions", "ListBucketMultipartUploads",
			"PutObject", "DeleteObjectVersion", "CopyObject", "DeleteObject",
			"CopyObjectPart", "PutObjectPart", "CompleteMultipartUpload", "NewMultipartUpload", "AbortMultipartUpload",
			"GetBucketAcl", "PutBucketAcl"}
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

func (ac_policy AccessControlPolicyMarshal) findUserRights(id ID, bucketOwner string) []Permission {
	var user_rights []Permission
	stringId := string(id)
	for _, grant := range ac_policy.AccessControlList.Grant {
		if grant.Grantee.ID == stringId ||
			(grant.Grantee.URI == AuthenticatedUsersGroup && stringId != "anonymous") ||
			grant.Grantee.URI == AllUsersGroup ||
			(grant.Grantee.URI == BucketOwnerGroup && bucketOwner != "" && stringId == bucketOwner) {
			if grant.Permission == PermissionFullControl {
				return []Permission{"FULL_CONTROL"}
			} else {
				user_rights = append(user_rights, grant.Permission)
			}
		}
	}
	return user_rights
}

func (id *ID) authzAcl(action Action, acPolicyObject AccessControlPolicyMarshal, acPolicyBucket AccessControlPolicyMarshal,
	bucketOwner string) bool {

	permissions_bucket := acPolicyBucket.findUserRights(*id, "")
	fmt.Printf("%+v", acPolicyBucket)
	fmt.Println(permissions_bucket)
	for _, permission := range permissions_bucket {
		for _, allowed_action := range AclMapBucket(permission) {
			if action == allowed_action {
				return true
			}
		}
	}

	permissions_object := acPolicyObject.findUserRights(*id, bucketOwner)
	for _, permission := range permissions_object {
		for _, allowed_action := range AclMapObject(permission) {
			if action == allowed_action {
				return true
			}
		}
	}

	return false
}
