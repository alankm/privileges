package privileges

import "errors"

// PrivelegedObject provides an interface to allow other packages to employ
// *nix style permissions on their objects.
type PrivelegedObject interface {
	Permissions() *Permissions
	Read(*Key, interface{}) (interface{}, error)
	Write(*Key, interface{}) (interface{}, error)
	Exec(*Key, interface{}) (interface{}, error)
}

var (
	maskDir  uint16 = 4096
	maskOwn  uint16 = 1792
	maskOwnR uint16 = 1024
	maskOwnW uint16 = 512
	maskOwnX uint16 = 256
	maskGrp  uint16 = 112
	maskGrpR uint16 = 64
	maskGrpW uint16 = 32
	maskGrpX uint16 = 16
	maskOth  uint16 = 7
	maskOthR uint16 = 4
	maskOthW uint16 = 2
	maskOthX uint16 = 1
)

// Permissions is a *nix-style file permissions object
type Permissions struct {
	owner string
	group string
	perms uint16
}

func (p *Permissions) getIsDir() bool {
	return p.perms&maskDir == maskDir
}

func (p *Permissions) setIsDir(a bool) {
	if a {
		p.perms = p.perms | maskDir
	} else {
		p.perms = p.perms & ^maskDir
	}
}

func (p *Permissions) getOwnR() bool {
	return p.perms&maskOwnR == maskOwnR
}

func (p *Permissions) getOwnW() bool {
	return p.perms&maskOwnW == maskOwnW
}

func (p *Permissions) getOwnX() bool {
	return p.perms&maskOwnX == maskOwnX
}

func (p *Permissions) getGrpR() bool {
	return p.perms&maskGrpR == maskGrpR
}

func (p *Permissions) getGrpW() bool {
	return p.perms&maskGrpW == maskGrpW
}

func (p *Permissions) getGrpX() bool {
	return p.perms&maskGrpX == maskGrpX
}

func (p *Permissions) getOthR() bool {
	return p.perms&maskOthR == maskOthR
}

func (p *Permissions) getOthW() bool {
	return p.perms&maskOthW == maskOthW
}

func (p *Permissions) getOthX() bool {
	return p.perms&maskOthX == maskOthX
}

func (p *Permissions) set(mod string) error {

	var err = errors.New("invalid mod string")
	switch len(mod) {
	case 4: // Octal mod string
		if mod[0] != '0' {
			return err
		}

		for i := 1; i < 4; i++ {
			if mod[i] < '0' || mod[i] > '7' {
				return err
			}
		}

		var a = uint16(mod[1] - '0')
		a = a<<4 | uint16(mod[2]-'0')
		a = a<<4 | uint16(mod[3]-'0')
		a = a | p.perms&maskDir
		p.perms = a

	default:
		return err
	}

	return nil

}

// Octal returns the octal representation of the file's permissions (0777)
func (p *Permissions) Octal() []rune {

	own := rune(p.perms>>8&7 + '0')
	grp := rune(p.perms>>4&7 + '0')
	oth := rune(p.perms&7 + '0')

	a := append([]rune("0"), own, grp, oth)
	return a

}

// Symbolic returns the symbolic representation of the file's permissions (rwx)
func (p *Permissions) Symbolic() []rune {

	var sym = []rune("----------")

	if p.getIsDir() {
		sym[0] = 'd'
	}

	if p.getOwnR() {
		sym[1] = 'r'
	}

	if p.getOwnW() {
		sym[2] = 'w'
	}

	if p.getOwnX() {
		sym[3] = 'x'
	}

	if p.getGrpR() {
		sym[4] = 'r'
	}

	if p.getGrpW() {
		sym[5] = 'w'
	}

	if p.getGrpX() {
		sym[6] = 'x'
	}

	if p.getOthR() {
		sym[7] = 'r'
	}

	if p.getOthW() {
		sym[8] = 'w'
	}

	if p.getOthX() {
		sym[9] = 'x'
	}

	return sym

}

// Full returns the symbolic representation of the file's permissions with the
// file's owner and associated group appended.
func (p *Permissions) Full() string {
	return string(p.Symbolic()) + " " + p.owner + " " + p.group
}

// Owner returns a string naming the user owner identified by the permissions
func (p *Permissions) Owner() string {
	return p.owner
}

// Group returns a string naming the group identified by the permissions
func (p *Permissions) Group() string {
	return p.group
}
