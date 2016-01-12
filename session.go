package privileges

type Privileged interface {
	Rules() *Rules
	Read(...string) interface{}
	Write(...string) interface{}
	Exec(...string) interface{}
}

type Session struct {
	p      *Privileges
	SID    string
	User   string
	Hash   string
	su     bool
	gid    string
	groups []string
	umask  string
}

func (s *Session) Logout() {

	delete(s.p.sessions, s.SID)

}

func (s *Session) NewUser(username, salt, hashword string) error {
	if !s.valid() {
		return errBadSession
	}

	if !s.su {
		return errNotSU
	}

	err := s.p.newUserHash(username, salt, hashword)
	return err

}

func (s *Session) ChangePassword(username, salt, hashword string) error {
	if !s.valid() {
		return errBadSession
	}

	if username == "" || username == s.User {
		s.p.changePassword(s.User, salt, hashword)
	} else if s.su {
		s.p.changePassword(username, salt, hashword)
	} else {
		return errDenied
	}

	return nil

}

func (s *Session) DeleteUser(username string) error {
	if !s.valid() {
		return errBadSession
	}

	if !s.su {
		return errNotSU
	}

	if username == s.User {
		return errDenied
	}

	s.p.deleteUser(username)

	return s.p.deleteUser(username)

}

func (s *Session) NewGroup(name string) error {
	if !s.valid() {
		return errBadSession
	}

	if !s.su {
		return errNotSU
	}

	return s.p.newGroup(name)
}

func (s *Session) DeleteGroup(name string) error {
	if !s.valid() {
		return errBadSession
	}

	if !s.su {
		return errNotSU
	}

	return s.p.deleteGroup(name)
}

func (s *Session) Gid(username, group string) (string, error) {

	if username == s.User || username == "" {
		if group == "" {
			return s.gid, nil
		}
		return "", s.p.setGid(s.User, group)
	}

	if group == "" {
		return s.p.gid(username)
	}
	return "", s.p.setGid(username, group)

}

func (s *Session) Umask(mask string) (string, error) {
	if mask == "" {
		return s.umask, nil
	}

	err := s.p.setUmask(mask, s.User)
	if err != nil {
		return "", err
	}

	s.umask = mask

	return "", nil

}

func (s *Session) UserAddGroup(username, group string) error {
	if !s.valid() {
		return errBadSession
	}

	if !s.su {
		return errNotSU
	}

	return s.p.addToGroup(username, group)

}

func (s *Session) UserInGroup(username, group string) (bool, error) {
	return s.p.inGroup(username, group)
}

func (s *Session) UserRemoveGroup(username, group string) error {
	if !s.valid() {
		return errBadSession
	}

	if !s.su {
		return errNotSU
	}

	return s.p.removeFromGroup(username, group)

}

func (s *Session) ListUsers() ([]string, error) {
	return s.p.listUsers()
}

func (s *Session) ListGroups() ([]string, error) {
	return s.p.listGroups()
}

func (s *Session) UserListGroups(username string) ([]string, error) {
	return s.p.userListGroups(username)
}

func (s *Session) GroupListUsersGids(group string) ([]string, error) {
	return s.p.listUsersWithGid(group)
}

func (s *Session) valid() bool {

	_, ok := s.p.sessions[s.SID]
	return ok

}

func (s *Session) CanRead(p Privileged) bool {
	r := p.Rules()
	if s.User == r.Owner() {
		return r.rules>>8&4 == 4
	}

	for _, g := range s.groups {
		if g == r.Group() {
			return r.rules>>4&4 == 4
		}
	}

	return r.rules&4 == 4

}

func (s *Session) Read(p Privileged, args ...string) (interface{}, error) {
	if s.CanRead(p) {
		return p.Read(args...), nil
	}
	return nil, errDenied

}

func (s *Session) CanWrite(p Privileged) bool {
	r := p.Rules()
	if s.User == r.Owner() {
		return r.rules>>8&2 == 2
	}

	for _, g := range s.groups {
		if g == r.Group() {
			return r.rules>>4&2 == 2
		}
	}

	return r.rules&2 == 2
}

func (s *Session) Write(p Privileged, args ...string) (interface{}, error) {
	if s.CanWrite(p) {
		return p.Write(args...), nil
	}
	return nil, errDenied
}

func (s Session) CanExec(p Privileged) bool {
	r := p.Rules()
	if s.User == r.Owner() {
		return r.rules>>8&1 == 1
	}

	for _, g := range s.groups {
		if g == r.Group() {
			return r.rules>>4&1 == 1
		}
	}

	return r.rules&1 == 1
}

func (s *Session) Exec(p Privileged, args ...string) (interface{}, error) {
	if s.CanExec(p) {
		return p.Exec(args...), nil
	}
	return nil, errDenied
}

func (s *Session) CanChgrp(r *Rules, group string) bool {
	in := false
	for _, grp := range s.groups {
		if grp == group {
			in = true
			break
		}
	}

	if in && r.Owner() == s.User {
		return true
	}

	if in && s.su {
		return true
	}

	if s.su {
		rows, err := s.p.db.Query("SELECT * FROM groups WHERE name=?", group)
		if err != nil {
			return false
		}
		defer rows.Close()

		if rows.Next() {
			return true
		}
	}

	return false

}

func (s *Session) CanChown(r *Rules, owner string) bool {

	if s.su {
		rows, err := s.p.db.Query("SELECT * FROM users WHERE name=?", owner)
		if err != nil {
			return false
		}
		defer rows.Close()

		if rows.Next() {
			return true
		}
	}

	return false

}

func (s *Session) CanChmod(r *Rules, mode string) bool {

	if !validRules(mode) {
		return false
	}

	if r.Owner() == s.User || s.su {
		return true
	}

	return false

}
