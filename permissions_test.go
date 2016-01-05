package privileges

import "testing"

func TestPermissionsGets(t *testing.T) {

	var perm = Permissions{
		owner: "root",
		group: "root",
		perms: maskDir | maskOwn | maskGrp | maskOth,
	}

	PrettyError(t, "root", perm.Owner())
	PrettyError(t, "root", perm.Group())
	PrettyError(t, "0777", string(perm.Octal()))
	PrettyError(t, "drwxrwxrwx root root", string(perm.Full()))

	err := perm.set("0007")
	if err != nil {
		t.Error(nil)
	}
	PrettyError(t, "d------rwx root root", string(perm.Full()))

	perm.setIsDir(false)
	err = perm.set("0052")
	if err != nil {
		t.Error(nil)
	}
	PrettyError(t, "----r-x-w- root root", string(perm.Full()))

	perm.setIsDir(true)
	err = perm.set("0134")
	if err != nil {
		t.Error(nil)
	}
	PrettyError(t, "d--x-wxr-- root root", string(perm.Full()))

	err = perm.set("01340")
	if err == nil {
		t.Error(nil)
	}

	err = perm.set("1134")
	if err == nil {
		t.Error(nil)
	}

	err = perm.set("0194")
	if err == nil {
		t.Error(nil)
	}

}

func PrettyError(t *testing.T, expected, actual string) {
	if expected != actual {
		t.Errorf("\nEXPECT: %v\nACTUAL: %v", expected, actual)
	}
}
