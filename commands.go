package privileges

import (
	"database/sql"
	"errors"
)

var (
	errDenied = errors.New("access denied")
)

// Privileges provides a handle to access the Privileges database and methods.
type Privileges struct {
	db   *sql.DB
	path string
}

// Key contains validation information required to determine what permissions
// the user has when they attempt to execute any functions.
type Key struct {
	p        *Privileges
	username string
	hashword string
}

// New creates the privileges database at the provided path and returns a handle
// for use by other packages.
func New(path string) (*Privileges, error) {

	return loadDatabase(path)

}

// Login takes a raw username and password string provided by a client and
// returns a key with their credentials for Privileges functions if the
// credentials are accepted. Otherwise an error is thrown.
func (p *Privileges) Login(username, password string) (*Key, error) {

	key := new(Key)
	key.username = username
	key.p = p
	err := p.login(key, password)
	return key, err

}

// NewUser creates a new user with the provided username and password. The new
// user will not be part of any groups. Errors should only return if the user
// already exists or if the key does not have permission.
func (key *Key) NewUser(username, password string) error {

	if key.valid() && key.su() {
		return key.p.newUser(username, password)
	}

	return errDenied

}

// SetPassword changes a users password. If there exists a user with the
// username, that user's password will be changed to the provided password as
// long as the key has permission to do so (is the key of the user being changed
// or is the key of a user with super user privileges)
func (key *Key) SetPassword(user, password string) error {

	if key.valid() {

		if key.username == user {

			key.p.changePassword(user, password)
			k, err := key.p.Login(user, password)
			key.hashword = k.hashword
			return err

		} else if key.su() {
			return key.p.changePassword(user, password)
		}

	}

	return errDenied

}

// DeleteUser deletes the user with the given username, as long as the provided
// key has super user privileges and the target isn't root or the key.
func (key *Key) DeleteUser(user string) error {

	if key.valid() && key.su() {
		if user != key.username && user != rootName {
			return key.p.deleteUser(user)
		}
	}

	return errDenied

}

// NewGroup creates a new group with the provided name. Only returns error if
// a group with that name already exists or if a bad key was provided.
func (key *Key) NewGroup(name string) error {

	if key.valid() && key.su() {
		return key.p.newGroup(name)
	}

	return errDenied

}

// DeleteGroup deletes the group with the given name, as long as the provided
// key has super user privileges and the target isn't the root group.
func (key *Key) DeleteGroup(group string) error {

	if key.valid() && key.su() {
		if !(group == rootGroup) {
			return key.p.deleteGroup(group)
		}
	}

	return errDenied

}

// SetGid changes the user's gid to the provided group, provided that it exists.
func (key *Key) SetGid(user, group string) error {

	if key.valid() {
		if key.su() || (user == key.username && key.p.inGroup(user, group)) {
			return key.p.setGid(user, group)
		}
	}

	return errDenied

}

// Gid returns the user's gid.
func (key *Key) Gid(user string) string {

	return key.p.gid(user)

}

// AddToGroup adds an existing user to an existing group. Returns an error if
// the key is invalid or if the username or group do not exist.
func (key *Key) AddToGroup(user, group string) error {

	if key.valid() && key.su() {
		return key.p.addToGroup(user, group)
	}

	return errDenied

}

// InGroup returns true only if the provided key, username, and groupname
// are all valid, and the user is a member of the group. Otherwise false.
func (key *Key) InGroup(user, group string) bool {

	return key.p.inGroup(user, group)

}

// RemoveFromGroup removes the user from the group as long as the provided key
// has super user privileges and it is not attempting to remove root from the
// root group.
func (key *Key) RemoveFromGroup(user, group string) error {

	if key.valid() && key.su() {
		if !(user == rootName && group == rootGroup) {
			return key.p.removeFromGroup(user, group)
		}
	}

	return errDenied

}

// ListUsers returns a list of all the users in the system. No key is required.
func (key *Key) ListUsers() []string {

	return key.p.listUsers()

}

// ListGroups returns a list of groups that exist in Privileges. No key is
// required to view this list.
func (key *Key) ListGroups() []string {

	return key.p.listGroups()

}

// ListUsersGroups returns a list of all the groups a user belongs to. No key
// is required to view this list.
func (key *Key) ListUsersGroups(user string) []string {

	return key.p.listUsersGroups(user)

}

// ListUsersWithGid returns a list of all the users who currently have their gid
// set to the provided group.
func (key *Key) ListUsersWithGid(group string) []string {

	return key.p.listUsersWithGid(group)

}

// Chmod aims to be identical to the linux command as much as possible.
func (key *Key) Chmod(mod string, obj PrivelegedObject) error {

	if key.valid() && (key.su() || obj.Permissions().Owner() == key.username) {
		return obj.Permissions().set(mod)
	}

	return errDenied

}

// Chown aims to be identical to the linux command as much as possible.
func (key *Key) Chown(user string, obj PrivelegedObject) error {

	if key.valid() && key.su() && key.p.isUser(user) {
		obj.Permissions().owner = user
		return nil
	}

	return errDenied

}

// Chgrp aims to be identical to the linux command as much as possible.
func (key *Key) Chgrp(group string, obj PrivelegedObject) error {

	if key.valid() && key.p.isGroup(group) {

		if key.su() || (obj.Permissions().owner == key.username && key.p.inGroup(key.username, group)) {
			obj.Permissions().group = group
			return nil
		}

	}

	return errDenied

}
