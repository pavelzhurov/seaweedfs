package s3api

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"

	"github.com/chrislusf/seaweedfs/weed/glog"
	"github.com/chrislusf/seaweedfs/weed/pb/filer_pb"
	xhttp "github.com/chrislusf/seaweedfs/weed/s3api/http"
)

const (
	S3ACL_KEY = xhttp.AmzACL
)

func getBodyFromRequest(req *http.Request) ([]byte, error) {
	defer req.Body.Close()

	data, err := io.ReadAll(io.LimitReader(req.Body, req.ContentLength))
	if err != nil {
		return nil, fmt.Errorf("Read body: %v", err)
	}

	return data, nil
}

func (s3a *S3ApiServer) getACL(parentDirectoryPath string, entryName string) (ac_policy AccessControlPolicyMarshal, err error) {

	err = s3a.WithFilerClient(false, func(client filer_pb.SeaweedFilerClient) error {

		resp, err := filer_pb.LookupEntry(client, &filer_pb.LookupDirectoryEntryRequest{
			Directory: parentDirectoryPath,
			Name:      entryName,
		})
		if err != nil {
			return err
		}

		if resp.Entry.Extended == nil {
			return fmt.Errorf("%s has no AC policy", entryName)
		}

		if _, ok := resp.Entry.Extended[S3ACL_KEY]; !ok {
			return fmt.Errorf("%s has no AC policy", entryName)
		}

		ac_policy_unmarshal := &AccessControlPolicyUnmarshal{}
		xml.Unmarshal(resp.Entry.Extended[S3ACL_KEY], ac_policy_unmarshal)
		ac_policy = ac_policy_unmarshal.ConvertToMarshal()
		return nil
	})
	return
}

func (s3a *S3ApiServer) setACL(parentDirectoryPath string, entryName string, ac_policy []byte) (err error) {

	return s3a.WithFilerClient(false, func(client filer_pb.SeaweedFilerClient) error {

		resp, err := filer_pb.LookupEntry(client, &filer_pb.LookupDirectoryEntryRequest{
			Directory: parentDirectoryPath,
			Name:      entryName,
		})
		if err != nil {
			glog.V(3).Infof("Can't obtain entry: directory %s, name %s", parentDirectoryPath, entryName)
			return err
		}

		// Check policy format
		check_format := &AccessControlPolicyUnmarshal{}
		err = xml.Unmarshal(ac_policy, check_format)
		if err != nil {
			glog.V(3).Infof("Can't parse AC policy: %s", ac_policy)
			return fmt.Errorf("can't parse AC policy: %v", err)
		}

		// Check permissions
		for _, grant := range check_format.AccessControlList.Grant {
			ok := false
			for _, possible_permission := range ACL_PERMISSIONS {
				if grant.Permission == possible_permission {
					ok = true
					break
				}
			}
			if !ok {
				return fmt.Errorf("permission %v is not allowed. allowed permissions are %v", grant.Permission, ACL_PERMISSIONS)
			}
		}

		delete(resp.Entry.Extended, S3ACL_KEY)

		if resp.Entry.Extended == nil {
			resp.Entry.Extended = make(map[string][]byte)
		}

		resp.Entry.Extended[S3ACL_KEY] = ac_policy

		return filer_pb.UpdateEntry(client, &filer_pb.UpdateEntryRequest{
			Directory:          parentDirectoryPath,
			Entry:              resp.Entry,
			IsFromOtherCluster: false,
			Signatures:         nil,
		})

	})

}

// func (s3a *S3ApiServer) rmACL(parentDirectoryPath string, entryName string) (err error) {

// 	return s3a.WithFilerClient(false, func(client filer_pb.SeaweedFilerClient) error {

// 		resp, err := filer_pb.LookupEntry(client, &filer_pb.LookupDirectoryEntryRequest{
// 			Directory: parentDirectoryPath,
// 			Name:      entryName,
// 		})
// 		if err != nil {
// 			return err
// 		}

// 		if _, ok := resp.Entry.Extended[S3ACL_KEY]; ok {
// 			delete(resp.Entry.Extended, S3ACL_KEY)
// 		} else {
// 			return nil
// 		}

// 		return filer_pb.UpdateEntry(client, &filer_pb.UpdateEntryRequest{
// 			Directory:          parentDirectoryPath,
// 			Entry:              resp.Entry,
// 			IsFromOtherCluster: false,
// 			Signatures:         nil,
// 		})

// 	})

// }
