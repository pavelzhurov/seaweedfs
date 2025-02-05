package s3api

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"

	xhttp "github.com/chrislusf/seaweedfs/weed/s3api/http"

	"github.com/chrislusf/seaweedfs/weed/glog"
	"github.com/chrislusf/seaweedfs/weed/pb/filer_pb"
	"github.com/chrislusf/seaweedfs/weed/s3api/s3err"
	"github.com/chrislusf/seaweedfs/weed/util"
)

// GetObjectTaggingHandler - GET object tagging
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html
func (s3a *S3ApiServer) GetObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {

	bucket, object := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("GetObjectTaggingHandler %s %s", bucket, object)

	target := util.FullPath(fmt.Sprintf("%s/%s%s", s3a.option.BucketsPath, bucket, object))
	dir, name := target.DirAndName()

	tags, err := s3a.GetTags(dir, name)
	if err != nil {
		if err == filer_pb.ErrNotFound {
			glog.Errorf("GetObjectTaggingHandler %s: %v", r.URL, err)
			s3err.WriteErrorResponse(w, r, s3err.ErrNoSuchKey)
		} else {
			glog.Errorf("GetObjectTaggingHandler %s: %v", r.URL, err)
			s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		}
		return
	}

	writeSuccessResponseXML(w, r, FromTags(tags))

}

// PutObjectTaggingHandler Put object tagging
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectTagging.html
func (s3a *S3ApiServer) PutObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {

	bucket, object := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("PutObjectTaggingHandler %s %s", bucket, object)

	target := util.FullPath(fmt.Sprintf("%s/%s%s", s3a.option.BucketsPath, bucket, object))
	dir, name := target.DirAndName()

	tagging := &Tagging{}
	input, err := io.ReadAll(io.LimitReader(r.Body, r.ContentLength))
	if err != nil {
		glog.Errorf("PutObjectTaggingHandler read input %s: %v", r.URL, err)
		s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		return
	}
	if err = xml.Unmarshal(input, tagging); err != nil {
		glog.Errorf("PutObjectTaggingHandler Unmarshal %s: %v", r.URL, err)
		s3err.WriteErrorResponse(w, r, s3err.ErrMalformedXML)
		return
	}
	tags := tagging.ToTags()
	if len(tags) > 10 {
		glog.Errorf("PutObjectTaggingHandler tags %s: %d tags more than 10", r.URL, len(tags))
		s3err.WriteErrorResponse(w, r, s3err.ErrInvalidTag)
		return
	}
	for k, v := range tags {
		if len(k) > 128 {
			glog.Errorf("PutObjectTaggingHandler tags %s: tag key %s longer than 128", r.URL, k)
			s3err.WriteErrorResponse(w, r, s3err.ErrInvalidTag)
			return
		}
		if len(v) > 256 {
			glog.Errorf("PutObjectTaggingHandler tags %s: tag value %s longer than 256", r.URL, v)
			s3err.WriteErrorResponse(w, r, s3err.ErrInvalidTag)
			return
		}
	}

	if err = s3a.setTags(dir, name, tagging.ToTags()); err != nil {
		if err == filer_pb.ErrNotFound {
			glog.Errorf("PutObjectTaggingHandler setTags %s: %v", r.URL, err)
			s3err.WriteErrorResponse(w, r, s3err.ErrNoSuchKey)
		} else {
			glog.Errorf("PutObjectTaggingHandler setTags %s: %v", r.URL, err)
			s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	s3err.PostLog(r, http.StatusOK, s3err.ErrNone)
}

// DeleteObjectTaggingHandler Delete object tagging
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjectTagging.html
func (s3a *S3ApiServer) DeleteObjectTaggingHandler(w http.ResponseWriter, r *http.Request) {

	bucket, object := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("DeleteObjectTaggingHandler %s %s", bucket, object)

	target := util.FullPath(fmt.Sprintf("%s/%s%s", s3a.option.BucketsPath, bucket, object))
	dir, name := target.DirAndName()

	err := s3a.rmTags(dir, name)
	if err != nil {
		if err == filer_pb.ErrNotFound {
			glog.Errorf("DeleteObjectTaggingHandler %s: %v", r.URL, err)
			s3err.WriteErrorResponse(w, r, s3err.ErrNoSuchKey)
		} else {
			glog.Errorf("DeleteObjectTaggingHandler %s: %v", r.URL, err)
			s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
	s3err.PostLog(r, http.StatusNoContent, s3err.ErrNone)
}
