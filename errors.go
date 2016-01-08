package privileges

import "errors"

var (
	errGroupHasGids   = errors.New("can't delete group because it is gid for users")
	errRoot           = errors.New("can't perform this operation on root")
	errBadHash        = errors.New("bad hash")
	errBadSalt        = errors.New("bad salt")
	errBadName        = errors.New("bad group or user name")
	errDenied         = errors.New("access denied")
	errNotSU          = errors.New("only a superuser may perform this action")
	errBadRulesString = errors.New("bad rules string")
	errBadCredentials = errors.New("invalid username or password")
	errBadSession     = errors.New("invalid privileges session")
)
