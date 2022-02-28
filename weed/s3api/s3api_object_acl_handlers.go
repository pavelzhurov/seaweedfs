package s3api

import (
	"fmt"
	"net/http"

	xhttp "github.com/chrislusf/seaweedfs/weed/s3api/http"

	"github.com/chrislusf/seaweedfs/weed/glog"
	"github.com/chrislusf/seaweedfs/weed/pb/filer_pb"
	"github.com/chrislusf/seaweedfs/weed/s3api/s3err"
	"github.com/chrislusf/seaweedfs/weed/util"
)

// GetObjectAclHandler Put object ACL
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAcl.html
func (s3a *S3ApiServer) GetObjectAclHandler(w http.ResponseWriter, r *http.Request) {

	bucket, object := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("GetObjectAclHandler %s %s", bucket, object)

	target := util.FullPath(fmt.Sprintf("%s/%s%s", s3a.option.BucketsPath, bucket, object))
	dir, name := target.DirAndName()

	if err := s3a.checkObject(r, dir, name); err != s3err.ErrNone {
		s3err.WriteErrorResponse(w, r, err)
		return
	}

	ac_policy, err := s3a.getACL(dir, name)
	if err != nil {
		if err == filer_pb.ErrNotFound {
			glog.Errorf("Can't find ACL for object %s: %v", r.URL, err)
			s3err.WriteErrorResponse(w, r, s3err.ErrInvalidObjectState)
		} else {
			glog.Errorf("GetObjectAclHandler %s: %v", r.URL, err)
			s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		}
		return
	}

	writeSuccessResponseXML(w, r, ac_policy)

}

// PutObjectAclHandler Put object ACL
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectAcl.html
func (s3a *S3ApiServer) PutObjectAclHandler(w http.ResponseWriter, r *http.Request) {

	bucket, object := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("PutObjectTaggingHandler %s %s", bucket, object)

	target := util.FullPath(fmt.Sprintf("%s/%s%s", s3a.option.BucketsPath, bucket, object))
	dir, name := target.DirAndName()

	if err := s3a.checkObject(r, dir, name); err != s3err.ErrNone {
		s3err.WriteErrorResponse(w, r, err)
		return
	}

	acPolicyRaw, err := getBodyFromRequest(r)
	if err != nil {
		glog.V(3).Infof("Error while obtaining xml from request: %v", err)
		s3err.WriteErrorResponse(w, r, s3err.ErrMalformedXML)
		return
	}

	acPolicy, err := UnmarshalAndCheckACL(acPolicyRaw)
	if err != nil {
		glog.V(3).Infof("Error while marshalling ACL with grants from headers: %v", err)
		s3err.WriteErrorResponse(w, r, s3err.ErrMalformedACL)
		return
	}

	acPolicyBytes, errCode := s3a.AddOwnerAndPermissionsFromHeaders(acPolicy, r)
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
	glog.V(4).Infof("Object policy created: %s", acPolicyBytes)
	writeSuccessResponseEmpty(w, r)
}
