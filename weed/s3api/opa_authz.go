package s3api

import (
	"net/http"
	"encoding/json"
	"bytes"
	"io/ioutil"
	"os"
	"strings"

	"github.com/chrislusf/seaweedfs/weed/glog"
)

func (identity *Identity) authz(action Action, bucket string, object string, tags map[string]string) bool {
	glog.V(3).Infof("Action: %v, bucket: %v, object: %v, tags: %+v", action, bucket, object, tags)
	bucket_str := strings.Trim(bucket, "/")
	object_str := strings.Trim(object, "/")
	action_str := string(action)
	opa_input, _ := json.Marshal(map[string]interface{}{
		"partition": "pvc",
		"service": "S3",
		"account_id": "123",
		"project_id": "456",
		"resource_id": "789",
		"path": strings.Join([]string{bucket_str, object_str}, "/"),
		"action": action_str,
		"tags": tags,
		"user": identity.Name,
	})
	url := os.Getenv("OPA_URL")
	if url == "" {
		glog.V(1).Info("OPA URL is not provided")
		return false
	}
	response, err := http.Post(url, "application/json", bytes.NewBuffer(opa_input))
	//Handle Error
	if err != nil {
		glog.V(3).Infof("An Error Occured %v", err)
		return false
	}
	responseBody, _ := ioutil.ReadAll(response.Body)
	var resp bool
	err_body := json.Unmarshal(responseBody, &resp)
	if err_body != nil {
		glog.V(3).Infof("An Error Occured %v", err_body)
		return false
	}

	glog.V(3).Infof("%+v\n", resp)

	return resp
}