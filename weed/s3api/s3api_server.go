package s3api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/chrislusf/seaweedfs/weed/filer"
	"github.com/chrislusf/seaweedfs/weed/pb"
	"github.com/chrislusf/seaweedfs/weed/s3api/s3err"
	"github.com/chrislusf/seaweedfs/weed/security"
	"github.com/chrislusf/seaweedfs/weed/util"
	"github.com/gorilla/mux"
	"google.golang.org/grpc"
)

type S3ApiServerOption struct {
	Filer            pb.ServerAddress
	Port             int
	Config           string
	DomainName       string
	BucketsPath      string
	GrpcDialOption   grpc.DialOption
	AllowEmptyFolder bool
	JWTPublicKey     string
}

type S3ApiServer struct {
	option         *S3ApiServerOption
	iam            *IdentityAccessManagement
	randomClientId int32
	filerGuard     *security.Guard
}

func NewS3ApiServer(router *mux.Router, option *S3ApiServerOption) (s3ApiServer *S3ApiServer, err error) {
	v := util.GetViper()
	signingKey := v.GetString("jwt.filer_signing.key")
	v.SetDefault("jwt.filer_signing.expires_after_seconds", 10)
	expiresAfterSec := v.GetInt("jwt.filer_signing.expires_after_seconds")

	readSigningKey := v.GetString("jwt.filer_signing.read.key")
	v.SetDefault("jwt.filer_signing.read.expires_after_seconds", 60)
	readExpiresAfterSec := v.GetInt("jwt.filer_signing.read.expires_after_seconds")

	s3ApiServer = &S3ApiServer{
		option:         option,
		iam:            NewIdentityAccessManagement(option),
		randomClientId: util.RandomInt32(),
		filerGuard:     security.NewGuard([]string{}, signingKey, expiresAfterSec, readSigningKey, readExpiresAfterSec),
	}

	s3ApiServer.registerRouter(router)

	go s3ApiServer.subscribeMetaEvents("s3", filer.IamConfigDirecotry+"/"+filer.IamIdentityFile, time.Now().UnixNano())
	return s3ApiServer, nil
}

func (s3a *S3ApiServer) registerRouter(router *mux.Router) {
	// API Router
	apiRouter := router.PathPrefix("/").Subrouter()

	// Readiness Probe
	apiRouter.Methods("GET").Path("/status").HandlerFunc(s3a.StatusHandler)

	var routers []*mux.Router
	if s3a.option.DomainName != "" {
		domainNames := strings.Split(s3a.option.DomainName, ",")
		for _, domainName := range domainNames {
			routers = append(routers, apiRouter.Host(
				fmt.Sprintf("%s.%s:%d", "{bucket:.+}", domainName, s3a.option.Port)).Subrouter())
			routers = append(routers, apiRouter.Host(
				fmt.Sprintf("%s.%s", "{bucket:.+}", domainName)).Subrouter())
		}
	}
	routers = append(routers, apiRouter.PathPrefix("/{bucket}").Subrouter())

	for _, bucket := range routers {

		// each case should follow the next rule:
		// - requesting object with query must precede any other methods
		// - requesting object must precede any methods with buckets
		// - requesting bucket with query must precede raw methods with buckets
		// - requesting bucket must be processed in the end

		// objects with query

		// CopyObjectPart
		bucket.Methods("PUT").Path("/{object:.+}").HeadersRegexp("X-Amz-Copy-Source", `.*?(\/|%2F).*?`).HandlerFunc(track(s3a.iam.Auth(s3a.CopyObjectPartHandler, "CopyObjectPart", s3a), "PUT")).Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}")
		// PutObjectPart
		bucket.Methods("PUT").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.PutObjectPartHandler, "PutObjectPart", s3a), "PUT")).Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId:.*}")
		// CompleteMultipartUpload
		bucket.Methods("POST").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.CompleteMultipartUploadHandler, "CompleteMultipartUpload", s3a), "POST")).Queries("uploadId", "{uploadId:.*}")
		// NewMultipartUpload
		bucket.Methods("POST").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.NewMultipartUploadHandler, "NewMultipartUpload", s3a), "POST")).Queries("uploads", "")
		// AbortMultipartUpload
		bucket.Methods("DELETE").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.AbortMultipartUploadHandler, "AbortMultipartUpload", s3a), "DELETE")).Queries("uploadId", "{uploadId:.*}")
		// ListObjectParts
		bucket.Methods("GET").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.ListObjectPartsHandler, "ListObjectParts", s3a), "GET")).Queries("uploadId", "{uploadId:.*}")
		// ListMultipartUploads
		bucket.Methods("GET").HandlerFunc(track(s3a.iam.Auth(s3a.ListMultipartUploadsHandler, "ListMultipartUploads", s3a), "GET")).Queries("uploads", "")

		// GetObjectTagging
		bucket.Methods("GET").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.GetObjectTaggingHandler, "GetObjectTagging", s3a), "GET")).Queries("tagging", "")
		// PutObjectTagging
		bucket.Methods("PUT").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.PutObjectTaggingHandler, "PutObjectTagging", s3a), "PUT")).Queries("tagging", "")
		// DeleteObjectTagging
		bucket.Methods("DELETE").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.DeleteObjectTaggingHandler, "DeleteObjectTagging", s3a), "DELETE")).Queries("tagging", "")

		// PutObjectACL
		bucket.Methods("PUT").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.PutObjectAclHandler, "PutObjectAcl", s3a), "PUT")).Queries("acl", "")
		// PutObjectRetention
		bucket.Methods("PUT").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.PutObjectRetentionHandler, "PutObjectRetention", s3a), "PUT")).Queries("retention", "")
		// PutObjectLegalHold
		bucket.Methods("PUT").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.PutObjectLegalHoldHandler, "PutObjectLegalHold", s3a), "PUT")).Queries("legal-hold", "")
		// PutObjectLockConfiguration
		bucket.Methods("PUT").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.PutObjectLockConfigurationHandler, "PutObjectLockConfiguration", s3a), "PUT")).Queries("object-lock", "")

		// GetObjectACL
		bucket.Methods("GET").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.GetObjectAclHandler, "GetObjectAcl", s3a), "GET")).Queries("acl", "")

		// objects with query

		// raw objects

		// HeadObject
		bucket.Methods("HEAD").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.HeadObjectHandler, "HeadObject", s3a), "GET"))

		// GetObject, but directory listing is not supported
		bucket.Methods("GET").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.GetObjectHandler, "GetObject", s3a), "GET"))

		// CopyObject
		bucket.Methods("PUT").Path("/{object:.+}").HeadersRegexp("X-Amz-Copy-Source", ".*?(\\/|%2F).*?").HandlerFunc(track(s3a.iam.Auth(s3a.CopyObjectHandler, "CopyObject", s3a), "COPY"))
		// PutObject
		bucket.Methods("PUT").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.PutObjectHandler, "PutObject", s3a), "PUT"))
		// DeleteObject
		bucket.Methods("DELETE").Path("/{object:.+}").HandlerFunc(track(s3a.iam.Auth(s3a.DeleteObjectHandler, "DeleteObject", s3a), "DELETE"))

		// raw objects

		// buckets with query

		// DeleteMultipleObjects
		bucket.Methods("POST").HandlerFunc(track(s3a.iam.Auth(s3a.DeleteMultipleObjectsHandler, "DeleteMultipleObjects", s3a), "DELETE")).Queries("delete", "")

		// GetBucketACL
		bucket.Methods("GET").HandlerFunc(track(s3a.iam.Auth(s3a.GetBucketAclHandler, "GetBucketAcl", s3a), "GET")).Queries("acl", "")
		// PutBucketACL
		bucket.Methods("PUT").HandlerFunc(track(s3a.iam.Auth(s3a.PutBucketAclHandler, "PutBucketAcl", s3a), "PUT")).Queries("acl", "")

		// GetBucketPolicy
		bucket.Methods("GET").HandlerFunc(track(s3a.iam.Auth(s3a.GetBucketPolicyHandler, "GetBucketPolicy", s3a), "GET")).Queries("policy", "")
		// PutBucketPolicy
		bucket.Methods("PUT").HandlerFunc(track(s3a.iam.Auth(s3a.PutBucketPolicyHandler, "PutBucketPolicy", s3a), "PUT")).Queries("policy", "")
		// DeleteBucketPolicy
		bucket.Methods("DELETE").HandlerFunc(track(s3a.iam.Auth(s3a.DeleteBucketPolicyHandler, "DeleteBucketPolicy", s3a), "DELETE")).Queries("policy", "")

		// GetBucketCors
		bucket.Methods("GET").HandlerFunc(track(s3a.iam.Auth(s3a.GetBucketCorsHandler, "GetBucketCors", s3a), "GET")).Queries("cors", "")
		// PutBucketCors
		bucket.Methods("PUT").HandlerFunc(track(s3a.iam.Auth(s3a.PutBucketCorsHandler, "PutBucketCors", s3a), "PUT")).Queries("cors", "")
		// DeleteBucketCors
		bucket.Methods("DELETE").HandlerFunc(track(s3a.iam.Auth(s3a.DeleteBucketCorsHandler, "DeleteBucketCors", s3a), "DELETE")).Queries("cors", "")

		// GetBucketLifecycleConfiguration
		bucket.Methods("GET").HandlerFunc(track(s3a.iam.Auth(s3a.GetBucketLifecycleConfigurationHandler, "GetBucketLifecycleConfiguration", s3a), "GET")).Queries("lifecycle", "")
		// PutBucketLifecycleConfiguration
		bucket.Methods("PUT").HandlerFunc(track(s3a.iam.Auth(s3a.PutBucketLifecycleConfigurationHandler, "PutBucketLifecycleConfiguration", s3a), "PUT")).Queries("lifecycle", "")
		// DeleteBucketLifecycleConfiguration
		bucket.Methods("DELETE").HandlerFunc(track(s3a.iam.Auth(s3a.DeleteBucketLifecycleHandler, "DeleteBucketLifecycle", s3a), "DELETE")).Queries("lifecycle", "")

		// GetBucketLocation
		bucket.Methods("GET").HandlerFunc(track(s3a.iam.Auth(s3a.GetBucketLocationHandler, "GetBucketLocation", s3a), "GET")).Queries("location", "")

		// GetBucketRequestPayment
		bucket.Methods("GET").HandlerFunc(track(s3a.iam.Auth(s3a.GetBucketRequestPaymentHandler, "GetBucketRequestPayment", s3a), "GET")).Queries("requestPayment", "")

		// ListObjectsV2
		bucket.Methods("GET").HandlerFunc(track(s3a.iam.Auth(s3a.ListObjectsV2Handler, "ListBucket", s3a), "LIST")).Queries("list-type", "2")

		// buckets with query

		// raw buckets

		// PostPolicy
		bucket.Methods("POST").HeadersRegexp("Content-Type", "multipart/form-data*").HandlerFunc(track(s3a.iam.Auth(s3a.PostPolicyBucketHandler, "PostPolicyBucket", s3a), "POST"))

		// HeadBucket
		bucket.Methods("HEAD").HandlerFunc(track(s3a.iam.Auth(s3a.HeadBucketHandler, "HeadBucket", s3a), "GET"))

		// PutBucket
		bucket.Methods("PUT").HandlerFunc(track(s3a.iam.Auth(s3a.PutBucketHandler, "PutBucket", s3a), "PUT"))
		// DeleteBucket
		bucket.Methods("DELETE").HandlerFunc(track(s3a.iam.Auth(s3a.DeleteBucketHandler, "DeleteBucket", s3a), "DELETE"))

		// ListObjectsV1 (Legacy)
		bucket.Methods("GET").HandlerFunc(track(s3a.iam.Auth(s3a.ListObjectsV1Handler, "ListBucket", s3a), "LIST"))

		// raw buckets

	}

	// ListBuckets
	apiRouter.Methods("GET").Path("/").HandlerFunc(track(s3a.iam.Auth(s3a.ListBucketsHandler, "ListBuckets", s3a), "ListBuckets"))

	// NotFound
	apiRouter.NotFoundHandler = http.HandlerFunc(s3err.NotFoundHandler)

}
