package privileges

type Rules struct {
	owner string
	group string
	rules uint16
}

func (r *Rules) Rules() *Rules {
	return r
}

func (r *Rules) Read(args ...string) interface{} {
	return nil
}

func (r *Rules) Write(args ...string) interface{} {
	return nil
}

func (r *Rules) Exec(args ...string) interface{} {
	return nil
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
func (r *Rules) Octal() string {
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

func (r *Rules) Symbolic(directory bool) string {
	sym := []byte("----------")
	if directory {
		sym[0] = 'd'
	}

	if r.rules>>10&1 == 1 {
		sym[1] = 'r'
	}

	if r.rules>>9&1 == 1 {
		sym[2] = 'w'
	}

	if r.rules>>8&1 == 1 {
		sym[3] = 'x'
	}

	if r.rules>>6&1 == 1 {
		sym[4] = 'r'
	}

	if r.rules>>5&1 == 1 {
		sym[5] = 'w'
	}

	if r.rules>>4&1 == 1 {
		sym[6] = 'x'
	}

	if r.rules>>2&1 == 1 {
		sym[7] = 'r'
	}

	if r.rules>>1&1 == 1 {
		sym[8] = 'w'
	}

	if r.rules>>0&1 == 1 {
		sym[9] = 'x'
	}

	sym = append(sym, ' ')
	sym = append(sym, []byte(r.owner)...)

	sym = append(sym, ' ')
	sym = append(sym, []byte(r.group)...)

	return string(sym)
}
