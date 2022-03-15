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

func (s3a *S3ApiServer) GetOwner(parentDirectoryPath string, entryName string) (owner string, err error) {
	err = s3a.WithFilerClient(false, func(client filer_pb.SeaweedFilerClient) error {

		resp, err := filer_pb.LookupEntry(client, &filer_pb.LookupDirectoryEntryRequest{
			Directory: parentDirectoryPath,
			Name:      entryName,
		})
		if err != nil {
			return err
		}

		if resp.Entry.Extended == nil {
			return fmt.Errorf("%s has no owner", entryName)
		}

		if _, ok := resp.Entry.Extended[xhttp.AmzIdentityId]; !ok {
			return fmt.Errorf("%s has no owner", entryName)
		}

		owner = string(resp.Entry.Extended[xhttp.AmzIdentityId])

		if owner == "" {
			return fmt.Errorf("owner is empty")
		}

		return nil
	})
	return
}

func (s3a *S3ApiServer) setOwner(parentDirectoryPath, entryName string, owner ID) (err error) {
	return s3a.WithFilerClient(false, func(client filer_pb.SeaweedFilerClient) error {

		resp, err := filer_pb.LookupEntry(client, &filer_pb.LookupDirectoryEntryRequest{
			Directory: parentDirectoryPath,
			Name:      entryName,
		})
		if err != nil {
			glog.V(3).Infof("Can't obtain entry: directory %s, name %s", parentDirectoryPath, entryName)
			return err
		}

		if resp.Entry.Extended == nil {
			resp.Entry.Extended = make(map[string][]byte)
		}

		resp.Entry.Extended[xhttp.AmzIdentityId] = []byte(owner)

		return filer_pb.UpdateEntry(client, &filer_pb.UpdateEntryRequest{
			Directory:          parentDirectoryPath,
			Entry:              resp.Entry,
			IsFromOtherCluster: false,
			Signatures:         nil,
		})

	})
}

func (s3a *S3ApiServer) GetACL(parentDirectoryPath string, entryName string) (acPolicy AccessControlPolicyMarshal, err error) {

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

		acPolicyUnmarshal := &AccessControlPolicyUnmarshal{}
		xml.Unmarshal(resp.Entry.Extended[S3ACL_KEY], acPolicyUnmarshal)
		acPolicy = acPolicyUnmarshal.ConvertToMarshal()
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
