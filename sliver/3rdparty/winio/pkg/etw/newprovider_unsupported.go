// +build arm

package etw

import (
	"github.com/bishopfox/sliver/sliver/3rdparty/winio/pkg/guid"
)

// NewProviderWithID returns a nil provider on unsupported platforms.
func NewProviderWithID(name string, id guid.GUID, callback EnableCallback) (provider *Provider, err error) {
	return nil, nil
}
