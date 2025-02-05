package s3api

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/chrislusf/seaweedfs/weed/security"
	"github.com/chrislusf/seaweedfs/weed/util/mem"

	"github.com/chrislusf/seaweedfs/weed/filer"
	"github.com/pquerna/cachecontrol/cacheobject"

	xhttp "github.com/chrislusf/seaweedfs/weed/s3api/http"
	"github.com/chrislusf/seaweedfs/weed/s3api/s3err"

	"github.com/chrislusf/seaweedfs/weed/glog"
	"github.com/chrislusf/seaweedfs/weed/pb/filer_pb"
	weed_server "github.com/chrislusf/seaweedfs/weed/server"
	"github.com/chrislusf/seaweedfs/weed/util"

	authz_utils "github.com/pavelzhurov/authz-utils"
)

var (
	client *http.Client
)

func init() {
	client = &http.Client{Transport: &http.Transport{
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 1024,
	}}
}

func (s3a *S3ApiServer) checkObject(r *http.Request, parentDirectoryPath string, entryName string) s3err.ErrorCode {
	entry, err := s3a.getEntry(parentDirectoryPath, entryName)
	if entry == nil || err == filer_pb.ErrNotFound {
		// There is no Object not found error in AWS doc
		return s3err.ErrAccessDenied
	}

	return s3err.ErrNone
}

func mimeDetect(r *http.Request, dataReader io.Reader) io.ReadCloser {
	mimeBuffer := make([]byte, 512)
	size, _ := dataReader.Read(mimeBuffer)
	if size > 0 {
		r.Header.Set("Content-Type", http.DetectContentType(mimeBuffer[:size]))
		return io.NopCloser(io.MultiReader(bytes.NewReader(mimeBuffer[:size]), dataReader))
	}
	return io.NopCloser(dataReader)
}

func (s3a *S3ApiServer) PutObjectHandler(w http.ResponseWriter, r *http.Request) {

	// http://docs.aws.amazon.com/AmazonS3/latest/dev/UploadingObjects.html

	bucket, object := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("PutObjectHandler %s %s", bucket, object)

	errCode := s3a.checkBucketInCache(r, bucket)
	if errCode != s3err.ErrNone {
		s3err.WriteErrorResponse(w, r, errCode)
		return
	}

	_, err := validateContentMd5(r.Header)
	if err != nil {
		s3err.WriteErrorResponse(w, r, s3err.ErrInvalidDigest)
		return
	}

	if r.Header.Get("Cache-Control") != "" {
		if _, err = cacheobject.ParseRequestCacheControl(r.Header.Get("Cache-Control")); err != nil {
			s3err.WriteErrorResponse(w, r, s3err.ErrInvalidDigest)
			return
		}
	}

	if r.Header.Get("Expires") != "" {
		if _, err = time.Parse(http.TimeFormat, r.Header.Get("Expires")); err != nil {
			s3err.WriteErrorResponse(w, r, s3err.ErrInvalidDigest)
			return
		}
	}

	dataReader := r.Body
	rAuthType := getRequestAuthType(r)
	if s3a.iam.isEnabled() {
		var s3ErrCode s3err.ErrorCode
		switch rAuthType {
		case authTypeStreamingSigned:
			dataReader, s3ErrCode = s3a.iam.newSignV4ChunkedReader(r)
		case authTypeSignedV2, authTypePresignedV2:
			_, s3ErrCode = s3a.iam.isReqAuthenticatedV2(r)
		case authTypePresigned, authTypeSigned:
			_, s3ErrCode = s3a.iam.reqSignatureV4Verify(r)
		}
		if s3ErrCode != s3err.ErrNone {
			s3err.WriteErrorResponse(w, r, s3ErrCode)
			return
		}
	} else {
		if authTypeStreamingSigned == rAuthType {
			s3err.WriteErrorResponse(w, r, s3err.ErrAuthNotSetup)
			return
		}
	}
	defer dataReader.Close()

	username, id, errCode := s3a.GetUsernameAndId(r)
	if errCode != s3err.ErrNone {
		s3err.WriteErrorResponse(w, r, errCode)
		return
	}

	ac_policy, errCode := s3a.CreateACPolicyFromTemplate(id, username, r, true)
	if errCode != s3err.ErrNone {
		s3err.WriteErrorResponse(w, r, errCode)
		return
	}

	fn := func(entry *filer_pb.Entry) {
		if entry.Extended == nil {
			entry.Extended = make(map[string][]byte)
		}

		entry.Extended[xhttp.AmzIdentityId] = []byte(id)

		entry.Extended[S3ACL_KEY] = ac_policy
		glog.V(4).Infof("Created default access control policy. Object %s is owned by %s", bucket+object, username)
	}

	target := util.FullPath(fmt.Sprintf("%s/%s%s", s3a.option.BucketsPath, bucket, object))
	dir, name := target.DirAndName()

	if strings.HasSuffix(object, "/") {
		if err := s3a.mkdir(s3a.option.BucketsPath, bucket+object, fn); err != nil {
			s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
			return
		}
	} else {
		uploadUrl := s3a.toFilerUrl(bucket, object)
		if r.Header.Get("Content-Type") == "" {
			dataReader = mimeDetect(r, dataReader)
		}

		var etag string
		var errCode s3err.ErrorCode
	Loop:
		for header := range r.Header {
			switch header {
			case xhttp.AmzSSECustomerKey:
				plaintext, err := ioutil.ReadAll(dataReader)
				if err != nil {
					s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
					return
				}
				key, _ := base64.StdEncoding.DecodeString(r.Header[header][0])
				cipher, err := util.Encrypt(plaintext, []byte(key))
				if err != nil {
					glog.Errorf("Can't encrtypt with customer provided key: %v", err)
					s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
					return
				}
				r.Header.Set("Content-Length", strconv.Itoa(len(cipher)))
				hash := md5.New()
				r.Header.Set("Content-Md5", base64.StdEncoding.EncodeToString((hash.Sum(cipher))))
				encryptDataReader := ioutil.NopCloser(bytes.NewBuffer(cipher))

				etag, errCode = s3a.putToFiler(r, uploadUrl, encryptDataReader)
				break Loop
			case xhttp.AmzSSEKMSKeyId:
				cryptorEndpoint, err := s3a.setUpCryptorClient()
				if err != nil {
					glog.Error(err)
					s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
					return
				}

				keyID := r.Header[header][0]
				cryptorRequest, err := http.NewRequest("POST", cryptorEndpoint+"/encrypt/"+keyID, dataReader)
				if err != nil {
					glog.Errorf("couldn't form cryptor request %s: %v", cryptorEndpoint+"/encrypt/"+keyID, err)
					s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
					return
				}

				cryptorResp, postErr := s3a.client.Do(cryptorRequest)

				if postErr != nil {
					glog.Errorf("post to cryptor: %v", postErr)
					s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
					return
				}
				if cryptorResp.StatusCode != 200 {
					errBody, _ := ioutil.ReadAll(cryptorResp.Body)
					glog.Errorf("not successfull code %d form cryptor: %s", cryptorResp.StatusCode, errBody)
					s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
					return
				}
				defer cryptorResp.Body.Close()

				r.Header.Set("Content-Length", cryptorResp.Header.Get("Content-Length"))
				r.Header.Set("Content-Md5", cryptorResp.Header.Get("Content-Md5"))

				etag, errCode = s3a.putToFiler(r, uploadUrl, cryptorResp.Body)
				s3a.setSSEKeyID(dir, name, keyID)
				break Loop
			}
		}
		if etag == "" {
			etag, errCode = s3a.putToFiler(r, uploadUrl, dataReader)
		}

		if errCode != s3err.ErrNone {
			s3err.WriteErrorResponse(w, r, errCode)
			return
		}

		setEtag(w, etag)

		err = s3a.setACL(dir, name, ac_policy)
		if err != nil {
			glog.Errorf("Error while creating default Access Policy: %v", err)
			s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
			return
		}
		err = s3a.setOwner(dir, name, id)
		if err != nil {
			glog.Errorf("Error while setting owner: %v", err)
			s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
			return
		}
		glog.V(4).Infof("Created default access control policy. Object %s is owned by %s", bucket+object, username)
	}

	writeSuccessResponseEmpty(w, r)
}

func (s3a *S3ApiServer) setUpCryptorClient() (cryptorEndpoint string, err error) {
	cryptorEndpoint, ok := os.LookupEnv("CRYPTOR_ENDPOINT")
	if !ok {
		return cryptorEndpoint, fmt.Errorf("Cryptor endpoint is not provided")
	}

	splittedEndpoint := strings.Split(cryptorEndpoint, "//")
	if len(splittedEndpoint) < 2 {
		return cryptorEndpoint, fmt.Errorf("Bad cryptor endpoint")
	}

	tlsConfig := &tls.Config{
		ServerName: splittedEndpoint[1],
	}
	_, ok = os.LookupEnv("SPIFFE_CLIENT")
	if ok {
		caCertString, ok := os.LookupEnv("KNOX_SERVER_CA")
		if !ok {
			return cryptorEndpoint, fmt.Errorf("knox CA cert is not provided")
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(caCertString))
		certs, err := authz_utils.LoadCertificates("/certs/*.key", "/certs/*.pem")
		if err == nil {
			tlsConfig.Certificates = certs
			tlsConfig.RootCAs = caCertPool
		}
	} else {
		return cryptorEndpoint, fmt.Errorf("SPIFFE certs are not provided")
	}

	s3a.client.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	
	return
}

func urlPathEscape(object string) string {
	var escapedParts []string
	for _, part := range strings.Split(object, "/") {
		escapedParts = append(escapedParts, url.PathEscape(part))
	}
	return strings.Join(escapedParts, "/")
}

func (s3a *S3ApiServer) toFilerUrl(bucket, object string) string {
	destUrl := fmt.Sprintf("http://%s%s/%s%s",
		s3a.option.Filer.ToHttpAddress(), s3a.option.BucketsPath, bucket, urlPathEscape(object))
	return destUrl
}

func (s3a *S3ApiServer) GetObjectHandler(w http.ResponseWriter, r *http.Request) {

	bucket, object := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("GetObjectHandler %s %s", bucket, object)

	if strings.HasSuffix(r.URL.Path, "/") {
		s3err.WriteErrorResponse(w, r, s3err.ErrNotImplemented)
		return
	}

	destUrl := s3a.toFilerUrl(bucket, object)

	s3a.proxyToFiler(w, r, destUrl, false, s3a.decryptIfNecessary)
}

func (s3a *S3ApiServer) HeadObjectHandler(w http.ResponseWriter, r *http.Request) {

	bucket, object := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("HeadObjectHandler %s %s", bucket, object)

	destUrl := s3a.toFilerUrl(bucket, object)

	s3a.proxyToFiler(w, r, destUrl, false, passThroughResponse)
}

func (s3a *S3ApiServer) DeleteObjectHandler(w http.ResponseWriter, r *http.Request) {

	bucket, object := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("DeleteObjectHandler %s %s", bucket, object)

	destUrl := s3a.toFilerUrl(bucket, object)

	s3a.proxyToFiler(w, r, destUrl, true, func(proxyResponse *http.Response, w http.ResponseWriter) (statusCode int) {
		statusCode = http.StatusNoContent
		for k, v := range proxyResponse.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(statusCode)
		return statusCode
	})
}

// / ObjectIdentifier carries key name for the object to delete.
type ObjectIdentifier struct {
	ObjectName string `xml:"Key"`
}

// DeleteObjectsRequest - xml carrying the object key names which needs to be deleted.
type DeleteObjectsRequest struct {
	// Element to enable quiet mode for the request
	Quiet bool
	// List of objects to be deleted
	Objects []ObjectIdentifier `xml:"Object"`
}

// DeleteError structure.
type DeleteError struct {
	Code    string
	Message string
	Key     string
}

// DeleteObjectsResponse container for multiple object deletes.
type DeleteObjectsResponse struct {
	XMLName xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ DeleteResult" json:"-"`

	// Collection of all deleted objects
	DeletedObjects []ObjectIdentifier `xml:"Deleted,omitempty"`

	// Collection of errors deleting certain objects.
	Errors []DeleteError `xml:"Error,omitempty"`
}

// DeleteMultipleObjectsHandler - Delete multiple objects
func (s3a *S3ApiServer) DeleteMultipleObjectsHandler(w http.ResponseWriter, r *http.Request) {

	bucket, _ := xhttp.GetBucketAndObject(r)
	glog.V(3).Infof("DeleteMultipleObjectsHandler %s", bucket)

	deleteXMLBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		return
	}

	deleteObjects := &DeleteObjectsRequest{}
	if err := xml.Unmarshal(deleteXMLBytes, deleteObjects); err != nil {
		s3err.WriteErrorResponse(w, r, s3err.ErrMalformedXML)
		return
	}

	var deletedObjects []ObjectIdentifier
	var deleteErrors []DeleteError
	var auditLog *s3err.AccessLog

	directoriesWithDeletion := make(map[string]int)

	if s3err.Logger != nil {
		auditLog = s3err.GetAccessLog(r, http.StatusNoContent, s3err.ErrNone)
	}
	s3a.WithFilerClient(false, func(client filer_pb.SeaweedFilerClient) error {

		// delete file entries
		for _, object := range deleteObjects.Objects {
			lastSeparator := strings.LastIndex(object.ObjectName, "/")
			parentDirectoryPath, entryName, isDeleteData, isRecursive := "", object.ObjectName, true, false
			if lastSeparator > 0 && lastSeparator+1 < len(object.ObjectName) {
				entryName = object.ObjectName[lastSeparator+1:]
				parentDirectoryPath = "/" + object.ObjectName[:lastSeparator]
			}
			parentDirectoryPath = fmt.Sprintf("%s/%s%s", s3a.option.BucketsPath, bucket, parentDirectoryPath)

			err := doDeleteEntry(client, parentDirectoryPath, entryName, isDeleteData, isRecursive)
			if err == nil {
				directoriesWithDeletion[parentDirectoryPath]++
				deletedObjects = append(deletedObjects, object)
			} else if strings.Contains(err.Error(), filer.MsgFailDelNonEmptyFolder) {
				deletedObjects = append(deletedObjects, object)
			} else {
				delete(directoriesWithDeletion, parentDirectoryPath)
				deleteErrors = append(deleteErrors, DeleteError{
					Code:    "",
					Message: err.Error(),
					Key:     object.ObjectName,
				})
			}
			if auditLog != nil {
				auditLog.Key = entryName
				s3err.PostAccessLog(*auditLog)
			}
		}

		// purge empty folders, only checking folders with deletions
		for len(directoriesWithDeletion) > 0 {
			directoriesWithDeletion = s3a.doDeleteEmptyDirectories(client, directoriesWithDeletion)
		}

		return nil
	})

	deleteResp := DeleteObjectsResponse{}
	if !deleteObjects.Quiet {
		deleteResp.DeletedObjects = deletedObjects
	}
	deleteResp.Errors = deleteErrors

	writeSuccessResponseXML(w, r, deleteResp)

}

func (s3a *S3ApiServer) doDeleteEmptyDirectories(client filer_pb.SeaweedFilerClient, directoriesWithDeletion map[string]int) (newDirectoriesWithDeletion map[string]int) {
	var allDirs []string
	for dir := range directoriesWithDeletion {
		allDirs = append(allDirs, dir)
	}
	sort.Slice(allDirs, func(i, j int) bool {
		return len(allDirs[i]) > len(allDirs[j])
	})
	newDirectoriesWithDeletion = make(map[string]int)
	for _, dir := range allDirs {
		parentDir, dirName := util.FullPath(dir).DirAndName()
		if parentDir == s3a.option.BucketsPath {
			continue
		}
		if err := doDeleteEntry(client, parentDir, dirName, false, false); err != nil {
			glog.V(4).Infof("directory %s has %d deletion but still not empty: %v", dir, directoriesWithDeletion[dir], err)
		} else {
			newDirectoriesWithDeletion[parentDir]++
		}
	}
	return
}

func (s3a *S3ApiServer) proxyToFiler(w http.ResponseWriter, r *http.Request, destUrl string, isWrite bool, responseFn func(proxyResponse *http.Response, w http.ResponseWriter) (statusCode int)) {

	glog.V(3).Infof("s3 proxying %s to %s", r.Method, destUrl)

	proxyReq, err := http.NewRequest(r.Method, destUrl, r.Body)

	if err != nil {
		glog.Errorf("NewRequest %s: %v", destUrl, err)
		s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		return
	}

	proxyReq.Header.Set("X-Forwarded-For", r.RemoteAddr)
	for k, v := range r.URL.Query() {
		if _, ok := xhttp.PassThroughHeaders[strings.ToLower(k)]; ok {
			proxyReq.Header[k] = v
		}
	}
	for header, values := range r.Header {
		proxyReq.Header[header] = values
	}

	// ensure that the Authorization header is overriding any previous
	// Authorization header which might be already present in proxyReq
	s3a.maybeAddFilerJwtAuthorization(proxyReq, isWrite)
	resp, postErr := s3a.client.Do(proxyReq)

	if postErr != nil {
		glog.Errorf("post to filer: %v", postErr)
		s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
		return
	}
	defer util.CloseResponse(resp)

	if resp.StatusCode == http.StatusPreconditionFailed {
		s3err.WriteErrorResponse(w, r, s3err.ErrPreconditionFailed)
		return
	}

	if (resp.ContentLength == -1 || resp.StatusCode == 404) && resp.StatusCode != 304 {
		if r.Method != "DELETE" {
			s3err.WriteErrorResponse(w, r, s3err.ErrNoSuchKey)
			return
		}
	}

	if keyID, ok := r.Header[xhttp.AmzSSECustomerKey]; ok {
		cipher, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
			return
		}
		key, _ := base64.StdEncoding.DecodeString(keyID[0])
		plaintext, err := util.Decrypt(cipher, key)
		if err != nil {
			glog.Errorf("couldn't decrypt data with provided key: %s. error: %v", key, err)
			s3err.WriteErrorResponse(w, r, s3err.ErrInternalError)
			return
		}
		resp.Header.Set("Content-Length", strconv.Itoa(len(plaintext)))
		hash := md5.New()
		resp.Header.Set("Content-Md5", base64.StdEncoding.EncodeToString((hash.Sum(plaintext))))
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(plaintext))
	}

	responseStatusCode := responseFn(resp, w)
	s3err.PostLog(r, responseStatusCode, s3err.ErrNone)
}

func (s3a *S3ApiServer) decryptIfNecessary(proxyResponse *http.Response, w http.ResponseWriter) (statusCode int) {
	if proxyResponse.Header.Get("Content-Range") != "" && proxyResponse.StatusCode == 200 {
		w.WriteHeader(http.StatusPartialContent)
		statusCode = http.StatusPartialContent
	} else {
		statusCode = proxyResponse.StatusCode
	}
	if keyID := proxyResponse.Header.Get(xhttp.AmzSSEKMSKeyId); keyID != "" {
		cryptorEndpoint, err := s3a.setUpCryptorClient()
		if err != nil {
			glog.Error(err)
			w.WriteHeader(500)
			return 500
		}

		cryptorRequest, err := http.NewRequest("POST", cryptorEndpoint+"/decrypt/"+keyID, proxyResponse.Body)
		if err != nil {
			glog.Errorf("couldn't form cryptor request %s: %v", cryptorEndpoint+"/decrypt/"+keyID, err)
			w.WriteHeader(500)
			return 500
		}
		// cryptorRequest.Header.Set("Authorization", token)

		cryptorResp, postErr := s3a.client.Do(cryptorRequest)

		if postErr != nil {
			glog.Errorf("post to cryptor: %v", postErr)
			w.WriteHeader(500)
			return 500
		}
		if cryptorResp.StatusCode != 200 {
			errBody, _ := ioutil.ReadAll(cryptorResp.Body)
			glog.Errorf("not successfull code %d form cryptor: %s", cryptorResp.StatusCode, errBody)
			w.WriteHeader(cryptorResp.StatusCode)
			return cryptorResp.StatusCode
		}
		proxyResponse.Body = cryptorResp.Body
	}
	w.WriteHeader(statusCode)
	buf := mem.Allocate(128 * 1024)
	defer mem.Free(buf)
	if n, err := io.CopyBuffer(w, proxyResponse.Body, buf); err != nil {
		glog.V(1).Infof("passthrough decrypted response read %d bytes: %v", n, err)
	}
	return statusCode
}

func passThroughResponse(proxyResponse *http.Response, w http.ResponseWriter) (statusCode int) {
	for k, v := range proxyResponse.Header {
		w.Header()[k] = v
	}
	if proxyResponse.Header.Get("Content-Range") != "" && proxyResponse.StatusCode == 200 {
		w.WriteHeader(http.StatusPartialContent)
		statusCode = http.StatusPartialContent
	} else {
		statusCode = proxyResponse.StatusCode
	}
	w.WriteHeader(statusCode)
	buf := mem.Allocate(128 * 1024)
	defer mem.Free(buf)
	if n, err := io.CopyBuffer(w, proxyResponse.Body, buf); err != nil {
		glog.V(1).Infof("passthrough response read %d bytes: %v", n, err)
	}
	return statusCode
}

func (s3a *S3ApiServer) putToFiler(r *http.Request, uploadUrl string, dataReader io.Reader) (etag string, code s3err.ErrorCode) {

	hash := md5.New()
	var body = io.TeeReader(dataReader, hash)

	proxyReq, err := http.NewRequest("PUT", uploadUrl, body)

	if err != nil {
		glog.Errorf("NewRequest %s: %v", uploadUrl, err)
		return "", s3err.ErrInternalError
	}

	proxyReq.Header.Set("X-Forwarded-For", r.RemoteAddr)

	for header, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(header, value)
		}
	}
	// ensure that the Authorization header is overriding any previous
	// Authorization header which might be already present in proxyReq
	s3a.maybeAddFilerJwtAuthorization(proxyReq, true)
	resp, postErr := s3a.client.Do(proxyReq)

	if postErr != nil {
		glog.Errorf("post to filer: %v", postErr)
		return "", s3err.ErrInternalError
	}
	defer resp.Body.Close()

	etag = fmt.Sprintf("%x", hash.Sum(nil))

	resp_body, ra_err := io.ReadAll(resp.Body)
	if ra_err != nil {
		glog.Errorf("upload to filer response read %d: %v", resp.StatusCode, ra_err)
		return etag, s3err.ErrInternalError
	}
	var ret weed_server.FilerPostResult
	unmarshal_err := json.Unmarshal(resp_body, &ret)
	if unmarshal_err != nil {
		glog.Errorf("failing to read upload to %s : %v", uploadUrl, string(resp_body))
		return "", s3err.ErrInternalError
	}
	if ret.Error != "" {
		glog.Errorf("upload to filer error: %v", ret.Error)
		return "", filerErrorToS3Error(ret.Error)
	}

	return etag, s3err.ErrNone
}

func setEtag(w http.ResponseWriter, etag string) {
	if etag != "" {
		if strings.HasPrefix(etag, "\"") {
			w.Header().Set("ETag", etag)
		} else {
			w.Header().Set("ETag", "\""+etag+"\"")
		}
	}
}

func filerErrorToS3Error(errString string) s3err.ErrorCode {
	switch {
	case strings.HasPrefix(errString, "existing ") && strings.HasSuffix(errString, "is a directory"):
		return s3err.ErrExistingObjectIsDirectory
	case strings.HasSuffix(errString, "is a file"):
		return s3err.ErrExistingObjectIsFile
	default:
		return s3err.ErrInternalError
	}
}

func (s3a *S3ApiServer) maybeAddFilerJwtAuthorization(r *http.Request, isWrite bool) {
	encodedJwt := s3a.maybeGetFilerJwtAuthorizationToken(isWrite)

	if encodedJwt == "" {
		return
	}

	r.Header.Set("Authorization", "BEARER "+string(encodedJwt))
}

func (s3a *S3ApiServer) maybeGetFilerJwtAuthorizationToken(isWrite bool) string {
	var encodedJwt security.EncodedJwt
	if isWrite {
		encodedJwt = security.GenJwtForFilerServer(s3a.filerGuard.SigningKey, s3a.filerGuard.ExpiresAfterSec)
	} else {
		encodedJwt = security.GenJwtForFilerServer(s3a.filerGuard.ReadSigningKey, s3a.filerGuard.ReadExpiresAfterSec)
	}
	return string(encodedJwt)
}
