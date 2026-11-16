// Package deploy carries the day-1 scripts: install-target.sh goes into
// every bundle `xdr controller add-target` makes.
package deploy

import _ "embed"

// InstallTarget is install-target.sh.
//
//go:embed install-target.sh
var InstallTarget []byte
