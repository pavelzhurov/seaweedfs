package s3api

import (
	"context"
	"encoding/xml"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/chrislusf/seaweedfs/weed/filer"
	"github.com/chrislusf/seaweedfs/weed/s3api/s3_constants"
	"github.com/chrislusf/seaweedfs/weed/storage/needle"
	"github.com/chrislusf/seaweedfs/weed/util"

	xhttp "github.com/chrislusf/seaweedfs/weed/s3api/http"
	"github.com/chrislusf/seaweedfs/weed/s3api/s3err"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/chrislusf/seaweedfs/weed/glog"
	"github.com/chrislusf/seaweedfs/weed/pb/filer_pb"
)

type ListAllMyBucketsResult struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListAllMyBucketsResult"`
	Owner   *s3.Owner
	Buckets []*s3.Bucket `xml:"Buckets>Bucket"`
}

func (s3a *S3ApiServer) ListBucketsHandler(w http.ResponseWriter, r *http.Request) {

	glog.V(3).Infof("ListBucketsHandler")

	var identity *Identity
	// Disable default authorization
	// if s3a.iam.isEnabled() {
	// 	identity, s3Err = s3a.iam.authUser(r)
	// 	if s3Err != s3err.ErrNone {
	// 		s3err.WriteErrorResponse(w, r, s3Err)
	// 		return
	// 	}
	// }

	var response ListAllMyBucketsResult

	entries, _, err := s3a.list(s3a.option.BucketsPath, "", "", false, math.MaxInt32)

	if err != nil {
		s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		return
	}

	identityId := r.Header.Get(xhttp.AmzIdentityId)

	var buckets []*s3.Bucket
	for _, entry := range entries {
		if entry.IsDirectory {
			if identity != nil && !identity.canDo(s3_constants.ACTION_LIST, entry.Name, "") {
				continue
			}
			buckets = append(buckets, &s3.Bucket{
				Name:         aws.String(entry.Name),
				CreationDate: aws.Time(time.Unix(entry.Attributes.Crtime, 0).UTC()),
			})
		}
	}

	response = ListAllMyBucketsResult{
		Owner: &s3.Owner{
			ID:          aws.String(identityId),
			DisplayName: aws.String(identityId),
		},
		Buckets: buckets,
	}

	writeSuccessResponseXML(w, r, response)
}

func (s3a *S3ApiServer) PutBucketHandler(w http.ResponseWriter, r *http.Request) {

	bucket, _ := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("PutBucketHandler %s", bucket)

	// avoid duplicated buckets
	errCode := s3err.ErrNone
	if err := s3a.WithFilerClient(false, func(client filer_pb.SeaweedFilerClient) error {
		if resp, err := client.CollectionList(context.Background(), &filer_pb.CollectionListRequest{
			IncludeEcVolumes:     true,
			IncludeNormalVolumes: true,
		}); err != nil {
			glog.Errorf("list collection: %v", err)
			return fmt.Errorf("list collections: %v", err)
		} else {
			for _, c := range resp.Collections {
				if bucket == c.Name {
					errCode = s3err.ErrBucketAlreadyExists
					break
				}
			}
		}
		return nil
	}); err != nil {
		s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		return
	}
	if exist, err := s3a.exists(s3a.option.BucketsPath, bucket, true); err == nil && exist {
		errCode = s3err.ErrBucketAlreadyExists
	}
	if errCode != s3err.ErrNone {
		s3err.WriteErrorResponse(w, r, errCode)
		return
	}

	username, id, errCode := s3a.GetUsernameAndId(r)
	if errCode != s3err.ErrNone {
		s3err.WriteErrorResponse(w, r, errCode)
		return
	}

	fn := func(entry *filer_pb.Entry) {
		if entry.Extended == nil {
			entry.Extended = make(map[string][]byte)
		}

		entry.Extended[xhttp.AmzIdentityId] = []byte(id)

		ac_policy, errCode := s3a.CreateACPolicyFromTemplate(id, username, r, false)
		if errCode != s3err.ErrNone {
			s3err.WriteErrorResponse(w, r, errCode)
			return
		}

		entry.Extended[S3ACL_KEY] = ac_policy
		glog.V(4).Infof("Created default access control policy. Bucket %s is owned by %s", bucket, username)
	}

	// create the folder for bucket, but lazily create actual collection
	if err := s3a.mkdir(s3a.option.BucketsPath, bucket, fn); err != nil {
		glog.Errorf("PutBucketHandler mkdir: %v", err)
		s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		return
	}
	writeSuccessResponseEmpty(w, r)
}

func (s3a *S3ApiServer) DeleteBucketHandler(w http.ResponseWriter, r *http.Request) {

	bucket, _ := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("DeleteBucketHandler %s", bucket)

	if err := s3a.checkBucket(r, bucket); err != s3err.ErrNone {
		s3err.WriteErrorResponse(w, r, err)
		return
	}

	entries, _, _ := s3a.list(s3a.option.BucketsPath+"/"+bucket, "", "", false, 1)

	// .uploads cleaning at background process, and is not visible to client in ListObjects,
	// so, if only entry is '.uploads' we can delete entire bucket
	if len(entries) != 0 && !(len(entries) == 1 && entries[0].Name == ".uploads") {
		s3err.WriteErrorResponse(w, r, s3err.ErrBucketNotEmpty)
		return
	}

	err := s3a.WithFilerClient(false, func(client filer_pb.SeaweedFilerClient) error {

		// delete collection
		deleteCollectionRequest := &filer_pb.DeleteCollectionRequest{
			Collection: bucket,
		}

		glog.V(1).Infof("delete collection: %v", deleteCollectionRequest)
		if _, err := client.DeleteCollection(context.Background(), deleteCollectionRequest); err != nil {
			return fmt.Errorf("delete collection %s: %v", bucket, err)
		}

		return nil
	})

	if err != nil {
		s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		return
	}

	err = s3a.rm(s3a.option.BucketsPath, bucket, false, true)

	if err != nil {
		s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		return
	}

	s3err.WriteEmptyResponse(w, r, http.StatusNoContent)
}

func (s3a *S3ApiServer) HeadBucketHandler(w http.ResponseWriter, r *http.Request) {

	bucket, _ := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("HeadBucketHandler %s", bucket)

	if entry, err := s3a.getEntry(s3a.option.BucketsPath, bucket); entry == nil || err == filer_pb.ErrNotFound {
		s3err.WriteErrorResponse(w, r, s3err.ErrNoSuchBucket)
		return
	}

	writeSuccessResponseEmpty(w, r)
}

func (s3a *S3ApiServer) checkBucket(r *http.Request, bucket string) s3err.ErrorCode {
	entry, err := s3a.getEntry(s3a.option.BucketsPath, bucket)
	if entry == nil || err == filer_pb.ErrNotFound {
		return s3err.ErrNoSuchBucket
	}

	return s3err.ErrNone
}

func (s3a *S3ApiServer) checkBucketInCache(r *http.Request, bucket string) s3err.ErrorCode {
	value := s3a.bucketsCache.Get(bucket)
	if value == nil || value.Expired() {
		glog.V(4).Info("Bucket not in the cache, checking existence")
		if code := s3a.checkBucket(r, bucket); code != s3err.ErrNone {
			return code
		}
		s3a.bucketsCache.Set(bucket, "", time.Second*time.Duration(s3a.option.BucketsCacheTTL))
		glog.V(4).Info("Bucket added to the cache")
	}
	glog.V(4).Info("Bucket in the cache")
	return s3err.ErrNone
}

func (s3a *S3ApiServer) hasAccess(r *http.Request, entry *filer_pb.Entry) bool {
	isAdmin := r.Header.Get(xhttp.AmzIsAdmin) != ""
	if isAdmin {
		return true
	}
	if entry.Extended == nil {
		return true
	}

	identityId := r.Header.Get(xhttp.AmzIdentityId)
	if id, ok := entry.Extended[xhttp.AmzIdentityId]; ok {
		if identityId != string(id) {
			return false
		}
	}
	return true
}

// GetBucketAclHandler Get Bucket ACL
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAcl.html
func (s3a *S3ApiServer) GetBucketAclHandler(w http.ResponseWriter, r *http.Request) {
	// collect parameters
	bucket, _ := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("GetBucketAclHandler %s", bucket)

	if err := s3a.checkBucket(r, bucket); err != s3err.ErrNone {
		s3err.WriteErrorResponse(w, r, err)
		return
	}

	target := util.FullPath(fmt.Sprintf("%s/%s", s3a.option.BucketsPath, bucket))
	dir, name := target.DirAndName()

	response, err := s3a.GetACL(dir, name)
	glog.V(4).Infof("Bucket policy: %+v", response)
	if err != nil {
		// For backward compabitility use old bucket ACL implementation, if bucket doesn't have AccessPolicy
		response = AccessControlPolicyMarshal{}
		response.XMLName = xml.Name{
			Space: "http://s3.amazonaws.com/doc/2006-03-01/",
			Local: "AccessControlPolicy",
		}
		for _, ident := range s3a.iam.identities {
			for _, action := range ident.Actions {
				if !action.overBucket(bucket) || action.getPermission() == "" {
					continue
				}
				if response.Owner.DisplayName == "" && action.isOwner(bucket) {
					response.Owner.DisplayName = ident.Name
					response.Owner.ID = ident.Name
				}
				response.AccessControlList.Grant = append(response.AccessControlList.Grant, Grant{
					Grantee: Grantee{
						ID:          ident.Name,
						DisplayName: ident.Name,
						Type:        "CanonicalUser",
						XMLXSI:      "CanonicalUser",
						XMLNS:       "http://www.w3.org/2001/XMLSchema-instance"},
					Permission: action.getPermission(),
				})
			}
		}
	}
	writeSuccessResponseXML(w, r, response)
}

// PutBucketAclHandler Put bucket ACL
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html
func (s3a *S3ApiServer) PutBucketAclHandler(w http.ResponseWriter, r *http.Request) {
	// collect parameters
	bucket, _ := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("PutBucketAclHandler %s", bucket)

	if err := s3a.checkBucket(r, bucket); err != s3err.ErrNone {
		s3err.WriteErrorResponse(w, r, err)
		return
	}

	target := util.FullPath(fmt.Sprintf("%s/%s", s3a.option.BucketsPath, bucket))
	dir, name := target.DirAndName()

	acPolicyRaw, err := getBodyFromRequest(r)
	if err != nil {
		glog.V(3).Infof("Error while obtaining xml from request: %v", err)
		s3err.WriteErrorResponse(w, r, s3err.ErrMalformedXML)
		return
	}

	acPolicy, err := UnmarshalAndCheckACL(acPolicyRaw)
	if err != nil {
		glog.V(3).Infof("Error while unmarshaling ACL: %v", err)
		s3err.WriteErrorResponse(w, r, s3err.ErrMalformedACL)
		return
	}

	id, err := s3a.GetOwner(dir, name)
	if err != nil {
		glog.V(3).Infof("Error while obtaining bucket owner: %v", err)
		s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		return
	}

	acPolicyBytes, errCode := s3a.AddOwnerAndPermissionsFromHeaders(acPolicy, r, false, id)
	if errCode != s3err.ErrNone {
		s3err.WriteErrorResponse(w, r, errCode)
		return
	}

	err = s3a.setACL(dir, name, acPolicyBytes)
	if err != nil {
		glog.V(3).Infof("Error while setting policy: %v", err)
		s3err.WriteErrorResponse(w, r, s3err.ErrMalformedACL)
		return
	}
	glog.V(4).Infof("Bucket policy created: %+v", acPolicy)
	writeSuccessResponseEmpty(w, r)
}

// GetBucketLifecycleConfigurationHandler Get Bucket Lifecycle configuration
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLifecycleConfiguration.html
func (s3a *S3ApiServer) GetBucketLifecycleConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	// collect parameters
	bucket, _ := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("GetBucketLifecycleConfigurationHandler %s", bucket)

	if err := s3a.checkBucket(r, bucket); err != s3err.ErrNone {
		s3err.WriteErrorResponse(w, r, err)
		return
	}
	fc, err := filer.ReadFilerConf(s3a.option.Filer, s3a.option.GrpcDialOption, nil)
	if err != nil {
		glog.Errorf("GetBucketLifecycleConfigurationHandler: %s", err)
		s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		return
	}
	ttls := fc.GetCollectionTtls(bucket)
	if len(ttls) == 0 {
		s3err.WriteErrorResponse(w, r, s3err.ErrNoSuchLifecycleConfiguration)
		return
	}
	response := Lifecycle{}
	for prefix, internalTtl := range ttls {
		ttl, _ := needle.ReadTTL(internalTtl)
		days := int(ttl.Minutes() / 60 / 24)
		if days == 0 {
			continue
		}
		response.Rules = append(response.Rules, Rule{
			Status: Enabled, Filter: Filter{
				Prefix: Prefix{string: prefix, set: true},
				set:    true,
			},
			Expiration: Expiration{Days: days, set: true},
		})
	}
	writeSuccessResponseXML(w, r, response)
}

// PutBucketLifecycleConfigurationHandler Put Bucket Lifecycle configuration
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html
func (s3a *S3ApiServer) PutBucketLifecycleConfigurationHandler(w http.ResponseWriter, r *http.Request) {

	s3err.WriteErrorResponse(w, r, s3err.ErrNotImplemented)

}

// DeleteBucketMetricsConfiguration Delete Bucket Lifecycle
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketLifecycle.html
func (s3a *S3ApiServer) DeleteBucketLifecycleHandler(w http.ResponseWriter, r *http.Request) {

	s3err.WriteEmptyResponse(w, r, http.StatusNoContent)

}

// GetBucketLocationHandler Get bucket location
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html
func (s3a *S3ApiServer) GetBucketLocationHandler(w http.ResponseWriter, r *http.Request) {
	writeSuccessResponseXML(w, r, LocationConstraint{})
}

// GetBucketRequestPaymentHandler Get bucket location
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketRequestPayment.html
func (s3a *S3ApiServer) GetBucketRequestPaymentHandler(w http.ResponseWriter, r *http.Request) {
	writeSuccessResponseXML(w, r, RequestPaymentConfiguration{Payer: "BucketOwner"})
}
