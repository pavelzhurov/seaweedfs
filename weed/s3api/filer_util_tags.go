package s3api

import (
	"strings"

	"github.com/chrislusf/seaweedfs/weed/pb/filer_pb"
	xhttp "github.com/chrislusf/seaweedfs/weed/s3api/http"
)

const (
	S3TAG_PREFIX = xhttp.AmzObjectTagging + "-"
)

func (s3a *S3ApiServer) GetTags(parentDirectoryPath string, entryName string) (tags map[string]string, err error) {

	err = s3a.WithFilerClient(false, func(client filer_pb.SeaweedFilerClient) error {

		resp, err := filer_pb.LookupEntry(client, &filer_pb.LookupDirectoryEntryRequest{
			Directory: parentDirectoryPath,
			Name:      entryName,
		})
		if err != nil {
			return err
		}
		tags = make(map[string]string)
		for k, v := range resp.Entry.Extended {
			if strings.HasPrefix(k, S3TAG_PREFIX) {
				tags[k[len(S3TAG_PREFIX):]] = string(v)
			}
		}
		return nil
	})
	return
}

func (s3a *S3ApiServer) setTags(parentDirectoryPath string, entryName string, tags map[string]string) (err error) {

	return s3a.WithFilerClient(false, func(client filer_pb.SeaweedFilerClient) error {

		resp, err := filer_pb.LookupEntry(client, &filer_pb.LookupDirectoryEntryRequest{
			Directory: parentDirectoryPath,
			Name:      entryName,
		})
		if err != nil {
			return err
		}

		for k := range resp.Entry.Extended {
			if strings.HasPrefix(k, S3TAG_PREFIX) {
				delete(resp.Entry.Extended, k)
			}
		}

		if resp.Entry.Extended == nil {
			resp.Entry.Extended = make(map[string][]byte)
		}
		for k, v := range tags {
			resp.Entry.Extended[S3TAG_PREFIX+k] = []byte(v)
		}

		return filer_pb.UpdateEntry(client, &filer_pb.UpdateEntryRequest{
			Directory:          parentDirectoryPath,
			Entry:              resp.Entry,
			IsFromOtherCluster: false,
			Signatures:         nil,
		})

	})

}

func (s3a *S3ApiServer) rmTags(parentDirectoryPath string, entryName string) (err error) {

	return s3a.WithFilerClient(false, func(client filer_pb.SeaweedFilerClient) error {

		resp, err := filer_pb.LookupEntry(client, &filer_pb.LookupDirectoryEntryRequest{
			Directory: parentDirectoryPath,
			Name:      entryName,
		})
		if err != nil {
			return err
		}

		hasDeletion := false
		for k := range resp.Entry.Extended {
			if strings.HasPrefix(k, S3TAG_PREFIX) {
				delete(resp.Entry.Extended, k)
				hasDeletion = true
			}
		}

		if !hasDeletion {
			return nil
		}

		return filer_pb.UpdateEntry(client, &filer_pb.UpdateEntryRequest{
			Directory:          parentDirectoryPath,
			Entry:              resp.Entry,
			IsFromOtherCluster: false,
			Signatures:         nil,
		})

	})

}
