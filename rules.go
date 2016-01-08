package privileges

type Rules struct {
	owner string
	group string
	rules uint16
}

func NewRules(owner, group, rules string) (*Rules, error) {
	if !validRules(rules) {
		return nil, errBadRulesString
	}

	var a uint16
	for i := 1; i < 4; i++ {
		a = a<<4 | uint16(rules[i]-'0')
	}
	r := new(Rules)
	r.owner = owner
	r.group = group
	r.rules = a
	return r, nil
}

func validRules(rules string) bool {
	if len(rules) != 4 || rules[0] != '0' {
		return false
	}
	for i := 1; i < 4; i++ {
		if rules[i] < '0' || rules[i] > '7' {
			return false
		}
	}
	return true
}

// Rules returns the octal representation of the file's permissions (0777)
func (r *Rules) Rules() string {
	a := []byte("0")
	for i := 2; i >= 0; i-- {
		a = append(a, byte(r.rules>>(4*uint(i))&7+'0'))
	}
	return string(a)
}

// Owner returns a string naming the user owner identified by the permissions
func (r *Rules) Owner() string {
	return r.owner
}

// Group returns a string naming the group identified by the permissions
func (r *Rules) Group() string {
	return r.group
}
