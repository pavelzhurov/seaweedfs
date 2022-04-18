package s3api

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/karlseguin/ccache/v2"

	"github.com/chrislusf/seaweedfs/weed/filer"
	"github.com/chrislusf/seaweedfs/weed/glog"
	"github.com/chrislusf/seaweedfs/weed/pb"
	"github.com/chrislusf/seaweedfs/weed/pb/filer_pb"
	"github.com/chrislusf/seaweedfs/weed/pb/iam_pb"
	xhttp "github.com/chrislusf/seaweedfs/weed/s3api/http"
	"github.com/chrislusf/seaweedfs/weed/s3api/s3_constants"
	"github.com/chrislusf/seaweedfs/weed/s3api/s3err"
	"github.com/chrislusf/seaweedfs/weed/util"

	authz_utils "github.com/pavelzhurov/authz-utils"
)

var MaxDuration = time.Duration(1<<63 - 1)

type Action string

type Iam interface {
	Check(f http.HandlerFunc, actions ...Action) http.HandlerFunc
}

type IdentityAccessManagement struct {
	m sync.RWMutex

	identities map[AccessKey]*Identity
	domain     string
	RSAPubKey  *rsa.PublicKey
	Authorizer *authz_utils.Authorizer
	KnoxClient *authz_utils.KnoxClient
}

type Identity struct {
	Name        IdentityName
	Credentials *ccache.Cache
	Actions     []Action
}

type Credential struct {
	AccessKey AccessKey
	SecretKey SecretKey
}

type IdentityName = string
type AccessKey = string
type SecretKey = string

type AuthS3API interface {
	GetACL(parentDirectoryPath string, entryName string) (ac_policy AccessControlPolicyMarshal, err error)
	GetTags(parentDirectoryPath string, entryName string) (tags map[string]string, err error)
	GetBucketsPath() string
	GetUsernameAndId(request *http.Request) (username string, id ID, errCode s3err.ErrorCode)
	GetOwner(parentDirectoryPath string, entryName string) (owner string, err error)
}

func (s3a *S3ApiServer) GetBucketsPath() string {
	return s3a.option.BucketsPath
}

func (action Action) isAdmin() bool {
	return strings.HasPrefix(string(action), s3_constants.ACTION_ADMIN)
}

func (action Action) isOwner(bucket string) bool {
	return string(action) == s3_constants.ACTION_ADMIN+":"+bucket
}

func (action Action) overBucket(bucket string) bool {
	return strings.HasSuffix(string(action), ":"+bucket) || strings.HasSuffix(string(action), ":*")
}

func (action Action) getPermission() Permission {
	switch act := strings.Split(string(action), ":")[0]; act {
	case s3_constants.ACTION_ADMIN:
		return Permission("FULL_CONTROL")
	case s3_constants.ACTION_WRITE:
		return Permission("WRITE")
	case s3_constants.ACTION_READ:
		return Permission("READ")
	default:
		return Permission("")
	}
}

func NewIdentityAccessManagement(option *S3ApiServerOption) *IdentityAccessManagement {
	RSAParsedKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(option.JWTPublicKey))
	if err != nil && option.JWTPublicKey != "" {
		glog.Fatalf("couldn't parse JWT Public Key! Error: %v", err)
	}

	var authorizer *authz_utils.Authorizer
	fmt.Printf("%+v\n", option)
	if option.IAMEnabled {
		authorizer, err = authz_utils.NewAuthorizerFromEnv()
		if err != nil {
			glog.Fatalf("couldn't initialized OPA client: %v", err)
		}
		glog.V(3).Info("OPA authorization is enabled!")
	}

	var knoxClient *authz_utils.KnoxClient
	if option.KMSEnabled {
		knoxClient, err = authz_utils.NewKnoxClientFromEnv()
		if err != nil {
			glog.Fatalf("couldn't initialized OPA client: %v", err)
		}
		glog.V(3).Info("Knox synchronization is enabled!")
	}

	iam := &IdentityAccessManagement{
		domain:     option.DomainName,
		RSAPubKey:  RSAParsedKey,
		Authorizer: authorizer,
		KnoxClient: knoxClient,
	}

	if option.Config != "" {
		if err := iam.loadS3ApiConfigurationFromFile(option.Config); err != nil {
			glog.Fatalf("fail to load config file %s: %v", option.Config, err)
		}
	} else {
		if err := iam.loadS3ApiConfigurationFromFiler(option); err != nil {
			glog.Warningf("fail to load config: %v", err)
		}
	}
	return iam
}

func (iam *IdentityAccessManagement) loadS3ApiConfigurationFromFiler(option *S3ApiServerOption) (err error) {
	var content []byte
	err = pb.WithFilerClient(false, option.Filer, option.GrpcDialOption, func(client filer_pb.SeaweedFilerClient) error {
		content, err = filer.ReadInsideFiler(client, filer.IamConfigDirecotry, filer.IamIdentityFile)
		return err
	})
	if err != nil {
		return fmt.Errorf("read S3 config: %v", err)
	}
	return iam.loadS3ApiConfigurationFromBytes(content)
}

func (iam *IdentityAccessManagement) loadS3ApiConfigurationFromFile(fileName string) error {
	content, readErr := os.ReadFile(fileName)
	if readErr != nil {
		glog.Warningf("fail to read %s : %v", fileName, readErr)
		return fmt.Errorf("fail to read %s : %v", fileName, readErr)
	}
	return iam.loadS3ApiConfigurationFromBytes(content)
}

func (iam *IdentityAccessManagement) loadS3ApiConfigurationFromBytes(content []byte) error {
	s3ApiConfiguration := &iam_pb.S3ApiConfiguration{}
	if err := filer.ParseS3ConfigurationFromBytes(content, s3ApiConfiguration); err != nil {
		glog.Warningf("unmarshal error: %v", err)
		return fmt.Errorf("unmarshal error: %v", err)
	}
	if err := iam.loadS3ApiConfiguration(s3ApiConfiguration); err != nil {
		return err
	}
	return nil
}

func (iam *IdentityAccessManagement) loadS3ApiConfiguration(config *iam_pb.S3ApiConfiguration) error {
	identities := make(map[IdentityName]*Identity)
	for _, ident := range config.Identities {
		t := &Identity{
			Name:        ident.Name,
			Credentials: nil,
			Actions:     nil,
		}
		for _, action := range ident.Actions {
			t.Actions = append(t.Actions, Action(action))
		}
		for _, cred := range ident.Credentials {
			t.Credentials.Set(cred.AccessKey, cred.SecretKey, MaxDuration)
		}
		identities[ident.Name] = t
	}
	iam.m.Lock()
	// atomically switch
	iam.identities = identities
	iam.m.Unlock()
	return nil
}

func (iam *IdentityAccessManagement) isEnabled() bool {
	iam.m.RLock()
	defer iam.m.RUnlock()
	return len(iam.identities) > 0
}

func (iam *IdentityAccessManagement) lookupByAccessKey(accessKey string) (identity *Identity, cred *Credential, found bool) {
	iam.m.RLock()
	defer iam.m.RUnlock()
	if iam.identities == nil {
		return nil, nil, false
	}
	for _, ident := range iam.identities {
		if ident != nil && ident.Credentials != nil {
			item := ident.Credentials.Get(accessKey)
			if item != nil {
				if item.Expired() && iam.KnoxClient != nil {
					updatedItem := iam.updateIndentity(accessKey)
					if updatedItem != nil {
						cred = &Credential{
							AccessKey: accessKey,
							SecretKey: updatedItem.Value().(string),
						}
						return ident, cred, true
					} else {
						ident.Credentials.Delete(accessKey)
					}
				} else {
					cred = &Credential{
						AccessKey: accessKey,
						SecretKey: item.Value().(string),
					}
					return ident, cred, true
				}
			}
		}
	}
	if iam.KnoxClient != nil {
		// updateIdentity adds keys which Knox Client returned before accessKey
		// and, more importantly, range won't iterate over new elements in map
		// That's why, if we didn't find accessKey, we should check Knox for new keys
		iam.updateIndentity("")
		for _, ident := range iam.identities {
			if ident != nil && ident.Credentials != nil {
				item := ident.Credentials.Get(accessKey)
				// In this case, it's impossible to have Expired keys
				if item != nil {
					cred = &Credential{
						AccessKey: accessKey,
						SecretKey: item.Value().(string),
					}
					return ident, cred, true
				}
			}
		}
	}
	glog.V(1).Infof("could not find accessKey %s", accessKey)
	return nil, nil, false
}

func (iam *IdentityAccessManagement) updateIndentity(accessKey string) (result *ccache.Item) {
	s3keys, err := iam.KnoxClient.SyncKeysFromKnox()
	if err != nil {
		glog.Warning("could not sync with Knox")
		glog.V(3).Infof("Knox error: %v", err)
	}
	for _, s3key := range s3keys {
		if identity, ok := iam.identities[s3key.Name]; ok {
			identity.Credentials.Set(s3key.AccessKey, s3key.SecretKey, 5*time.Minute)
		} else {
			credentials := ccache.New(ccache.Configure())
			credentials.Set(s3key.AccessKey, s3key.SecretKey, 5*time.Minute)
			iam.identities[s3key.Name] = &Identity{
				Name:        s3key.Name,
				Credentials: credentials,
				Actions:     nil,
			}
		}

		if accessKey != "" && accessKey == s3key.AccessKey {
			result = iam.identities[s3key.Name].Credentials.Get(accessKey)
			return
		}
	}
	return
}

func (iam *IdentityAccessManagement) lookupAnonymous() (identity *Identity, found bool) {
	iam.m.RLock()
	defer iam.m.RUnlock()
	if ident, ok := iam.identities["anonymous"]; ok {
		return ident, true
	}
	return nil, false
}

func (iam *IdentityAccessManagement) Auth(f http.HandlerFunc, action Action, s3api AuthS3API) http.HandlerFunc {
	if !iam.isEnabled() {
		return f
	}

	return func(w http.ResponseWriter, r *http.Request) {
		identity, errCode := iam.AuthRequest(r, action, s3api)
		if errCode == s3err.ErrNone {
			if identity != nil && identity.Name != "" {
				r.Header.Set(xhttp.AmzIdentityId, identity.Name)
				if identity.isAdmin() {
					r.Header.Set(xhttp.AmzIsAdmin, "true")
				} else if _, ok := r.Header[xhttp.AmzIsAdmin]; ok {
					r.Header.Del(xhttp.AmzIsAdmin)
				}
			}
			f(w, r)
			return
		}
		s3err.WriteErrorResponse(w, r, errCode)
	}
}

// check whether the request has valid access keys
func (iam *IdentityAccessManagement) AuthRequest(r *http.Request, action Action, s3api AuthS3API) (*Identity, s3err.ErrorCode) {
	var identity *Identity
	var s3Err s3err.ErrorCode
	var found bool
	var authType string
	switch getRequestAuthType(r) {
	case authTypeStreamingSigned:
		return identity, s3err.ErrNone
	case authTypeUnknown:
		glog.V(3).Infof("unknown auth type")
		r.Header.Set(xhttp.AmzAuthType, "Unknown")
		return identity, s3err.ErrAccessDenied
	case authTypePresignedV2, authTypeSignedV2:
		glog.V(3).Infof("v2 auth type")
		identity, s3Err = iam.isReqAuthenticatedV2(r)
		authType = "SigV2"
	case authTypeSigned, authTypePresigned:
		glog.V(3).Infof("v4 auth type")
		identity, s3Err = iam.reqSignatureV4Verify(r)
		authType = "SigV4"
	case authTypePostPolicy:
		glog.V(3).Infof("post policy auth type")
		r.Header.Set(xhttp.AmzAuthType, "PostPolicy")
		return identity, s3err.ErrNone
	case authTypeJWT:
		glog.V(3).Infof("jwt auth type")
		identity, s3Err = iam.parseJWT(r)
	case authTypeAnonymous:
		authType = "Anonymous"
		identity, found = iam.lookupAnonymous()
		if !found {
			r.Header.Set(xhttp.AmzAuthType, authType)
			return identity, s3err.ErrAccessDenied
		}
	default:
		return identity, s3err.ErrNotImplemented
	}

	if len(authType) > 0 {
		r.Header.Set(xhttp.AmzAuthType, authType)
	}
	if s3Err != s3err.ErrNone || action == s3_constants.ACTION_ADMIN {
		return identity, s3Err
	}

	glog.V(3).Infof("user name: %v actions: %v, action: %v", identity.Name, identity.Actions, action)

	bucket, object := xhttp.GetBucketAndObject(r)
	target := util.FullPath(fmt.Sprintf("%s/%s%s", s3api.GetBucketsPath(), bucket, object))
	dir, name := target.DirAndName()

	acPolicyObject := AccessControlPolicyMarshal{}
	if object != "/" {
		var err error
		acPolicyObject, err = s3api.GetACL(dir, name)
		if err != nil {
			glog.Errorf("can't get target %s acl: %v", target, err)
		}
	}

	targetBucket := util.FullPath(fmt.Sprintf("%s/%s", s3api.GetBucketsPath(), bucket))
	dirBucket, nameBucket := targetBucket.DirAndName()
	acPolicyBucket, err := s3api.GetACL(dirBucket, nameBucket)
	if err != nil {
		glog.Errorf("can't get target %s acl: %v", target, err)
	}
	bucketOwner, err := s3api.GetOwner(dirBucket, nameBucket)
	if err != nil {
		glog.Errorf("can't get bucket %s ownwer: %v", target, err)
	}

	// get_username_and_id returns error code only if AuthRequest return it, so there is no need to check it
	_, id, _ := s3api.GetUsernameAndId(r)

	tags, err := s3api.GetTags(dir, name)
	if err != nil {
		glog.Errorf("No tags for %s: %v", r.URL, err)
	}

	var iamDecision bool
	if iam.Authorizer != nil {
		iamDecision, err = iam.Authorizer.Authz("pvc", "S3", identity.Name, string(action), bucket+object, tags)
		if err != nil {
			glog.V(1).Infof("Can't connect to OPA: %v", err)
		}
	} else {
		iamDecision = identity.canDo(action.ActionToConst(), bucket, object)
	}

	if !(id.authzAcl(action, acPolicyObject, acPolicyBucket, bucketOwner) || iamDecision) {
		return identity, s3err.ErrAccessDenied
	}

	return identity, s3err.ErrNone

}

func (iam *IdentityAccessManagement) parseJWT(r *http.Request) (*Identity, s3err.ErrorCode) {
	var identity *Identity
	tokenString := strings.Split(r.Header.Get("Authorization"), " ")[1]
	var token *jwt.Token
	var err error
	var isTokenValid bool
	if iam.RSAPubKey != nil {
		token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validating expected alg:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// RSA public key from Keycloak
			return iam.RSAPubKey, nil
		})
		if err != nil {
			glog.V(3).Infof("Error while parsing token: %v\nToken: %+v\n", err, token)
			return nil, s3err.ErrMalformedCredentialDate
		}
		isTokenValid = token.Valid
	} else {
		token, err = jwt.Parse(tokenString, nil)
		if token == nil {
			glog.V(3).Infof("Error while parsing token: %v\nToken: %+v\n", err, token)
			return nil, s3err.ErrMalformedCredentialDate
		}
		isTokenValid = true
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && isTokenValid {
		if username, ok := claims["sub"].(string); ok {
			identity = &Identity{
				// Knox doesn't support keyIDs with hyphens, but sub contains them. So, we replace them with underscores.
				Name:        strings.Replace(username, "-", "_", -1),
				Credentials: nil,
				Actions:     nil,
			}
			return identity, s3err.ErrNone
		}
	}
	glog.V(4).Infof("Something wrong with token: %v.", token)
	glog.V(4).Infof("Is token valid? %v", token.Valid)
	return nil, s3err.ErrMalformedCredentialDate
}

func (iam *IdentityAccessManagement) authUser(r *http.Request) (*Identity, s3err.ErrorCode) {
	var identity *Identity
	var s3Err s3err.ErrorCode
	var found bool
	var authType string
	switch getRequestAuthType(r) {
	case authTypeStreamingSigned:
		return identity, s3err.ErrNone
	case authTypeUnknown:
		glog.V(3).Infof("unknown auth type")
		r.Header.Set(xhttp.AmzAuthType, "Unknown")
		return identity, s3err.ErrAccessDenied
	case authTypePresignedV2, authTypeSignedV2:
		glog.V(3).Infof("v2 auth type")
		identity, s3Err = iam.isReqAuthenticatedV2(r)
		authType = "SigV2"
	case authTypeSigned, authTypePresigned:
		glog.V(3).Infof("v4 auth type")
		identity, s3Err = iam.reqSignatureV4Verify(r)
		authType = "SigV4"
	case authTypePostPolicy:
		glog.V(3).Infof("post policy auth type")
		r.Header.Set(xhttp.AmzAuthType, "PostPolicy")
		return identity, s3err.ErrNone
	case authTypeJWT:
		glog.V(3).Infof("jwt auth type")
		r.Header.Set(xhttp.AmzAuthType, "Jwt")
		return identity, s3err.ErrNotImplemented
	case authTypeAnonymous:
		authType = "Anonymous"
		identity, found = iam.lookupAnonymous()
		if !found {
			r.Header.Set(xhttp.AmzAuthType, authType)
			return identity, s3err.ErrAccessDenied
		}
	default:
		return identity, s3err.ErrNotImplemented
	}

	if len(authType) > 0 {
		r.Header.Set(xhttp.AmzAuthType, authType)
	}

	glog.V(3).Infof("auth error: %v", s3Err)
	if s3Err != s3err.ErrNone {
		return identity, s3Err
	}
	return identity, s3err.ErrNone
}

func (action Action) ActionToConst() Action {
	tagging := regexp.MustCompile("^.*Tag.*$")
	read := regexp.MustCompile("^.*(Get|Head).*$")
	list := regexp.MustCompile("^.*List.*$")

	switch {
	case tagging.Match([]byte(action)):
		return Action(s3_constants.ACTION_TAGGING)
	case read.Match([]byte(action)):
		return Action(s3_constants.ACTION_READ)
	case list.Match([]byte(action)):
		return Action(s3_constants.ACTION_LIST)
	default:
		return Action(s3_constants.ACTION_WRITE)
	}
}

func (identity *Identity) canDo(action Action, bucket string, objectKey string) bool {
	if identity.isAdmin() {
		return true
	}
	for _, a := range identity.Actions {
		if a == action {
			return true
		}
	}
	if bucket == "" {
		return false
	}
	target := string(action) + ":" + bucket + objectKey
	adminTarget := s3_constants.ACTION_ADMIN + ":" + bucket + objectKey
	limitedByBucket := string(action) + ":" + bucket
	adminLimitedByBucket := s3_constants.ACTION_ADMIN + ":" + bucket
	for _, a := range identity.Actions {
		act := string(a)
		if strings.HasSuffix(act, "*") {
			if strings.HasPrefix(target, act[:len(act)-1]) {
				return true
			}
			if strings.HasPrefix(adminTarget, act[:len(act)-1]) {
				return true
			}
		} else {
			if act == limitedByBucket {
				return true
			}
			if act == adminLimitedByBucket {
				return true
			}
		}
	}
	return false
}

func (identity *Identity) isAdmin() bool {
	for _, a := range identity.Actions {
		if a == "Admin" {
			return true
		}
	}
	return false
}
