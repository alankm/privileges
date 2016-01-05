package privileges

import (
	"database/sql"
	"io/ioutil"
	"os"
	"testing"
)

const (
	testDB = "./database_test.db"
	usrA   = "alan"
	pwdA   = "password"
)

// p to be a working database and b to be a broken one
var p, b *Privileges
var root, sudo, basic, bad *Key
var err error

func TestMain(m *testing.M) {

	os.Remove(testDB)
	defer os.Remove(testDB)
	p, _ = New(testDB)
	defer p.close()
	tSetup()
	m.Run()

}

func tSetup() {
	root, _ = p.Login(rootName, rootPass)
	bad = new(Key)
	bad.p = p
	bad.username = "broken"
	bad.hashword = "QWERTYUI"

	root.NewUser("guest", "")
	root.NewGroup("friends")
	basic, _ = p.Login("guest", "")
}

func TestLogin(t *testing.T) {
	_, err = p.Login(rootName, rootPass+rootPass)
	if err == nil {
		t.Error(nil)
	}

	_, err = p.Login(rootName+rootName, rootPass)
	if err == nil {
		t.Error(nil)
	}
}

func TestNewUser(t *testing.T) {
	err = bad.NewUser(usrA, pwdA)
	if err == nil {
		t.Error(nil)
	}

	err = root.NewUser(usrA, pwdA)
	if err != nil {
		t.Error(nil)
	}
}

func TestSetPass(t *testing.T) {
	err = root.SetPassword("zxc", "zxc")
	if err != nil {
		t.Error(nil)
	}

	err = root.SetPassword(rootName, "Apple")
	if err != nil {
		t.Error(nil)
	}

	err = root.SetPassword(rootName, rootPass)
	if err != nil {
		t.Error(nil)
	}

	err = bad.SetPassword("zxc", "zxc")
	if err == nil {
		t.Error(nil)
	}
}

func TestDelete(t *testing.T) {
	err = bad.DeleteUser("zxc")
	if err == nil {
		t.Error(nil)
	}

	err = root.DeleteUser(rootName)
	if err == nil {
		t.Error(nil)
	}

	root.NewUser("banana", "")
	err = root.DeleteUser("banana")
	if err != nil {
		t.Error(nil)
	}
}

func TestNewGroup(t *testing.T) {
	err = bad.NewGroup("asd")
	if err == nil {
		t.Error(nil)
	}

	err = root.NewGroup(rootName)
	if err == nil {
		t.Error(nil)
	}

	err = root.NewGroup("alpha")
	if err != nil {
		t.Error(nil)
	}
}

func TestDeleteGroup(t *testing.T) {
	err = bad.DeleteGroup("asd")
	if err == nil {
		t.Error(nil)
	}

	err = root.DeleteGroup(rootGroup)
	if err == nil {
		t.Error(nil)
	}

	root.NewGroup("bravo")
	err = root.DeleteGroup("bravo")
	if err != nil {
		t.Error(nil)
	}
}

func TestGid(t *testing.T) {
	s := root.Gid(rootName)
	if s != rootName {
		t.Error(nil)
	}

	err = root.SetGid(rootName, rootGroup)
	if err != nil {
		t.Error(nil)
	}

	root.SetGid(rootName, rootName)
	bad.SetGid(rootName, rootName)
}

func TestAddToGroup(t *testing.T) {
	err = bad.AddToGroup(rootName, rootGroup)
	if err == nil {
		t.Error(nil)
	}

	err = root.AddToGroup(rootName, rootGroup)
	if err == nil {
		t.Error(nil)
	}

	root.RemoveFromGroup(rootName, rootName)
	err = root.AddToGroup(rootName, rootName)
	if err != nil {
		t.Error(nil)
	}
}

func TestInGroup(t *testing.T) {
	if !root.InGroup(rootName, rootName) {
		t.Error(nil)
	}
}

func TestRemoveFromGroup(t *testing.T) {
	err = bad.RemoveFromGroup(rootName, rootName)
	if err == nil {
		t.Error(nil)
	}

	err = root.RemoveFromGroup(rootName, rootGroup)
	if err == nil {
		t.Error(nil)
	}

	err = root.RemoveFromGroup(rootName, rootName)
	if err != nil {
		t.Error(nil)
	}

	root.AddToGroup(rootName, rootName)
}

func TestLists(t *testing.T) {
	root.ListUsers()
	root.ListGroups()
	root.ListUsersGroups(rootName)
	root.ListUsersWithGid(rootName)
}

type testObj struct {
	perms *Permissions
}

func (p *testObj) Permissions() *Permissions {
	return p.perms
}

func (p *testObj) Read(key *Key, arg interface{}) (interface{}, error) {
	return nil, nil
}

func (p *testObj) Write(key *Key, arg interface{}) (interface{}, error) {
	return nil, nil
}

func (p *testObj) Exec(key *Key, arg interface{}) (interface{}, error) {
	return nil, nil
}

var perm = &Permissions{
	owner: rootName,
	group: rootGroup,
	perms: 0,
}

var priv = &testObj{
	perms: perm,
}

func TestPChown(t *testing.T) {

	PrettyError(t, "----------", string(perm.Symbolic()))

	err := basic.Chown("ninja", priv)
	if err == nil {
		t.Error(nil)
	}

	err = bad.Chown("guest", priv)
	if err == nil {
		t.Error(nil)
	}

	err = basic.Chown("guest", priv)
	if err == nil {
		t.Error(nil)
	}

	err = root.Chown("guest", priv)
	if err != nil {
		t.Error(nil)
	}

	PrettyError(t, "guest", priv.Permissions().Owner())

}

func TestChgrp(t *testing.T) {

	PrettyError(t, "----------", string(perm.Symbolic()))

	err := basic.Chgrp("ninja", priv)
	if err == nil {
		t.Error(nil)
	}

	err = bad.Chgrp("friends", priv)
	if err == nil {
		t.Error(nil)
	}

	err = basic.Chgrp(rootGroup, priv)
	if err == nil {
		t.Error(nil)
	}

	err = root.Chgrp(rootGroup, priv)
	if err != nil {
		t.Error(nil)
	}

	err = basic.Chgrp("friends", priv)
	if err == nil {
		t.Error(nil)
	}

	basic.Chown("guest", priv)
	basic.AddToGroup("guest", "friends")

	err = basic.Chgrp("friends", priv)
	if err == nil {
		t.Error(nil)
	}

	PrettyError(t, rootGroup, priv.Permissions().Group())

}

func TestChmod(t *testing.T) {

	PrettyError(t, "----------", string(perm.Symbolic()))

	err := bad.Chmod("friends", priv)
	if err == nil {
		t.Error(nil)
	}

	err = basic.Chmod("ninja", priv)
	if err == nil {
		t.Error(nil)
	}

	err = root.Chmod("ninja", priv)
	if err == nil {
		t.Error(nil)
	}

	err = root.Chmod("0777", priv)
	if err != nil {
		t.Error(nil)
	}

	PrettyError(t, "-rwxrwxrwx", string(priv.Permissions().Symbolic()))

	root.Chown("guest", priv)
	err = basic.Chmod("0007", priv)
	if err != nil {
		t.Error(nil)
	}

	PrettyError(t, "-------rwx", string(priv.Permissions().Symbolic()))

}

func TestBreakHash(t *testing.T) {
	_, err := hash("a", "a")
	if err == nil {
		t.Error(nil)
	}
}

func TestBrokenKey(t *testing.T) {
	root.hashword = "asd"
	root.NewUser("Ace", "")
}

func TestBrokenDB(t *testing.T) {

	b := &Privileges{}
	b.db, _ = sql.Open("sqlite3_with_foreign_keys", "./broken.db")
	defer os.Remove("./broken.db")
	defer b.close()

	b.createStandardEntries()

	val := b.listUsers()
	if val != nil {
		t.Error(nil)
	}

	val = b.listGroups()
	if val != nil {
		t.Error(nil)
	}

	val = b.listUsersGroups("alan")
	if val != nil {
		t.Error(nil)
	}

	err = b.changePassword("alan", "password")
	if err == nil {
		t.Error(nil)
	}

	b.listUsersWithGid("alan")

}

func TestBackup(t *testing.T) {

	p.Login(rootName, rootPass)
	root.NewGroup("backup")

	file, err := p.snapshot()
	if err != nil {
		t.Error(nil)
	}

	err = ioutil.WriteFile("./backup", file, 0777)
	if err != nil {
		t.Error(nil)
	}
	defer os.Remove("./backup")

	err = os.Remove(testDB)
	if err != nil {
		t.Error(nil)
	}

	err = p.restore("./backup2")
	if err == nil {
		t.Error(nil)
	}

	err = p.restore("./backup")
	if err != nil {
		t.Error(nil)
	}

}
