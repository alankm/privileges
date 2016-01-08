package privileges

import (
	"io/ioutil"
	"os"
	"testing"
)

var err error
var p *Privileges

func TestMain(m *testing.M) {
	p, err = New("./test")
	defer os.Remove("./test")
	m.Run()
	p.Close()

}

func TestDB000(t *testing.T) {

	p.Close()
	ioutil.WriteFile("./tf", []byte("hello, world!"), 0777)
	defer os.Remove("./tf")
	p, err = New("./tf")
	if err == nil {
		t.Error(nil)
	}

	p.Close()
	p, err = New("./test")
	if err != nil {
		t.Error(nil)
	}

}

func TestDB001(t *testing.T) {

	data, err := p.Snapshot()
	if err != nil {
		t.Error(nil)
	}

	err = p.Restore([]byte("hello, world!"))
	if err == nil {
		t.Error(nil)
	}

	////
	_, err = p.userListGroups("hi")
	if err == nil {
		t.Error(nil)
	}

	err = p.deleteGroup("hi")
	if err == nil {
		t.Error(nil)
	}

	_, err = p.listGroups()
	if err == nil {
		t.Error(nil)
	}

	_, err = p.listUsers()
	if err == nil {
		t.Error(nil)
	}
	////

	err = p.Restore(data)
	if err != nil {
		t.Error(nil)
	}

}

func TestDB002(t *testing.T) {

	_, err = p.Login("", "")
	if err != errBadCredentials {
		t.Error(nil)
	}

	_, err = p.Login(root, "")
	if err != errBadCredentials {
		t.Error(nil)
	}

	s, err := p.Login(root, rootPassword)
	if err != nil {
		t.Error(nil)
	}

	s.Logout()

}

func TestDB003(t *testing.T) {

	_, err = p.LoginHash("", "")
	if err != errBadCredentials {
		t.Error(nil)
	}

	_, err = p.LoginHash(root, "")
	if err != errBadCredentials {
		t.Error(nil)
	}

	s, err := p.Login(root, rootPassword)
	if err != nil {
		t.Error(nil)
	}

	s.Logout()

	s, err = p.LoginHash(root, s.Hash)
	if err != nil {
		t.Error(nil)
	}

	s.Logout()

}

func TestDB004(t *testing.T) {
	_, err = hash("XCVBNM", "")
	if err == nil {
		t.Error(nil)
	}
}

func TestDB005(t *testing.T) {
	err = p.newGroup("")
	if err != errBadName {
		t.Error(nil)
	}
}

func TestDB006(t *testing.T) {
	err = p.newUser("", "")
	if err != errBadName {
		t.Error(nil)
	}
}

func TestDB007(t *testing.T) {
	err = p.newUserHash("", "", "")
	if err != errBadName {
		t.Error(nil)
	}

	err = p.newUserHash("hacker", "", "")
	if err != errBadSalt {
		t.Error(nil)
	}

	err = p.newUserHash("hacker", "1234123412341234123412341234123412341234123412341234123412341234", "")
	if err != errBadHash {
		t.Error(nil)
	}

	err = p.newUserHash("hacker", "1234123412341234123412341234123412341234123412341234123412341234", "1234123412341234123412341234123412341234123412341234123412341234")
	if err != nil {
		t.Error(nil)
	}

	p.newGroup("ninja")
	err = p.newUserHash("ninja", "1234123412341234123412341234123412341234123412341234123412341234", "1234123412341234123412341234123412341234123412341234123412341234")
	if err == nil {
		t.Error(nil)
	}
}

func TestDB008(t *testing.T) {
	err = p.changePassword("", "", "")
	if err == nil {
		t.Error(nil)
	}

	err = p.changePassword(root, "", "")
	if err != errBadSalt {
		t.Error(nil)
	}

	err = p.changePassword(root, "1234123412341234123412341234123412341234123412341234123412341234", "")
	if err != errBadHash {
		t.Error(nil)
	}

	p.newUser("Cyril", "Figgis")

	err = p.changePassword("Cyril", "1234123412341234123412341234123412341234123412341234123412341234", "1234123412341234123412341234123412341234123412341234123412341234")
	if err == nil {
		t.Error(nil)
	}

	err = p.deleteGroup("Cyril")
	if err != errGroupHasGids {
		t.Error(nil)
	}

	err = p.deleteUser("Cyril")
	if err != nil {
		t.Error(nil)
	}

	err = p.deleteGroup("Cyril")
	if err != nil {
		t.Error(nil)
	}
}

func TestDB009(t *testing.T) {
	err = p.deleteUser(root)
	if err != errRoot {
		t.Error(nil)
	}
}

func TestDB010(t *testing.T) {
	err = p.deleteGroup(root)
	if err != errRoot {
		t.Error(nil)
	}

}

func TestDB011(t *testing.T) {
	err = p.setGid("", "")
	if err != nil {
		t.Error(nil)
	}

	_, err = p.gid("")
	if err == nil {
		t.Error(nil)
	}
}

func TestDB012(t *testing.T) {
	err = p.setUmask("asd", root)
	if err != errBadRulesString {
		t.Error(nil)
	}

	err = p.setUmask("0000", root)
	if err != nil {
		t.Error(nil)
	}
}

func TestDB013(t *testing.T) {
	err = p.removeFromGroup("", "")
	if err != nil {
		t.Error(nil)
	}
}

func TestDB014(t *testing.T) {
	_, err := p.listGroups()
	if err != nil {
		t.Error(nil)
	}

	_, err = p.listUsers()
	if err != nil {
		t.Error(nil)
	}
}
