package privileges

import (
	"testing"
)

func TestRules00(t *testing.T) {
	_, err := NewRules("alan", "sisatech", "")
	if err != errBadRulesString {
		t.Error(nil)
	}
}

func TestRules01(t *testing.T) {
	_, err := NewRules("alan", "sisatech", "1111")
	if err != errBadRulesString {
		t.Error(nil)
	}
}

func TestRules02(t *testing.T) {
	_, err := NewRules("alan", "sisatech", "0A11")
	if err != errBadRulesString {
		t.Error(nil)
	}
}

func TestRules03(t *testing.T) {
	_, err := NewRules("alan", "sisatech", "07A1")
	if err != errBadRulesString {
		t.Error(nil)
	}
}

func TestRules04(t *testing.T) {
	_, err := NewRules("alan", "sisatech", "074B")
	if err != errBadRulesString {
		t.Error(nil)
	}
}

func TestRules05(t *testing.T) {
	r, err := NewRules("alan", "sisatech", "0740")
	if err != nil {
		t.Error(nil)
	}

	if r.Rules() != "0740" {
		t.Error(nil)
	}

	if r.Owner() != "alan" {
		t.Error(nil)
	}

	if r.Group() != "sisatech" {
		t.Error(nil)
	}
}
