package privileges

import (
	"crypto/rand"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"io/ioutil"

	sqlite3 "github.com/mattn/go-sqlite3"
)

var (
	root         = "root"
	rootPassword = "guest"
)

type Privileges struct {
	sessions map[string]bool
	db       *sql.DB
	path     string
}

type record struct {
	name  string
	salt  string
	pass  string
	gid   string
	umask string
}

func New(path string) (*Privileges, error) {

	p := new(Privileges)
	p.path = path
	p.db, _ = sql.Open("sqlite3_fk", p.path)
	err := p.setup()
	if err != nil {
		return p, err
	}
	p.sessions = make(map[string]bool)

	return p, nil

}

func (p *Privileges) Close() {

	p.db.Close()

}

func (p *Privileges) Snapshot() ([]byte, error) {

	return ioutil.ReadFile(p.path)

}

func (p *Privileges) Restore(snapshot []byte) error {

	p.Close()
	ioutil.WriteFile(p.path, snapshot, 0775)
	p.db, _ = sql.Open("sqlite3_fk", p.path)
	return p.setup()

}

func (p *Privileges) Login(username, password string) (*Session, error) {

	rec := new(record)
	row := p.db.QueryRow("SELECT * FROM users WHERE name=?", username)
	err := row.Scan(&rec.name, &rec.salt, &rec.pass, &rec.gid, &rec.umask)
	if err != nil {
		return nil, errBadCredentials
	}

	hashword, err := hash(rec.salt, password)
	if err != nil || hashword != rec.pass {
		return nil, errBadCredentials
	}

	s := new(Session)
	s.p = p
	s.User = username
	s.Hash = hashword
	s.gid = rec.gid
	s.umask = rec.umask
	s.SID = string(generateSalt64())
	s.groups, _ = p.userListGroups(username)
	s.su, _ = p.inGroup(username, root)
	p.sessions[s.SID] = true

	return s, nil

}

func (p *Privileges) LoginHash(username, hashword string) (*Session, error) {

	rec := new(record)
	row := p.db.QueryRow("SELECT * FROM users WHERE name=?", username)
	err := row.Scan(&rec.name, &rec.salt, &rec.pass, &rec.gid, &rec.umask)
	if err != nil {
		return nil, errBadCredentials
	}

	if err != nil || hashword != rec.pass {
		return nil, errBadCredentials
	}

	s := new(Session)
	s.p = p
	s.User = username
	s.Hash = hashword
	s.gid = rec.gid
	s.umask = rec.umask
	s.SID = string(generateSalt64())
	s.groups, _ = p.userListGroups(username)
	s.su, _ = p.inGroup(username, root)
	p.sessions[s.SID] = true

	return s, nil

}

func init() {
	sql.Register("sqlite3_fk",
		&sqlite3.SQLiteDriver{
			ConnectHook: func(conn *sqlite3.SQLiteConn) error {
				_, err := conn.Exec("PRAGMA foreign_keys = ON", nil)
				return err
			},
		})
}

func hash(salt, password string) (string, error) {

	rawSalt, err := hex.DecodeString(salt)
	if err != nil {
		return "", err
	}

	hasher := sha512.New()
	hasher.Write(rawSalt)
	hasher.Write([]byte(password))
	hashStr := hex.EncodeToString(hasher.Sum(nil))

	return hashStr, nil

}

func generateSalt64() []byte {

	salt := make([]byte, 64)
	rand.Read(salt)
	return salt

}

func saltAndHash(password string) (string, string) {

	salt := generateSalt64()
	hasher := sha512.New()
	hasher.Write(salt)
	hasher.Write([]byte(password))

	saltStr := hex.EncodeToString(salt)
	hashStr := hex.EncodeToString(hasher.Sum(nil))

	return saltStr, hashStr

}

func (p *Privileges) setup() error {

	var err error
	err = p.createGroupsTable()
	if err != nil {
		return err
	}

	p.createUsersTable()
	p.createUsersGroupsTable()
	p.createStandardEntries()

	return nil

}

func (p *Privileges) createGroupsTable() error {

	_, err := p.db.Exec("CREATE TABLE IF NOT EXISTS groups (name VARCHAR(64) PRIMARY KEY);")
	return err

}

func (p *Privileges) createUsersTable() {

	p.db.Exec("CREATE TABLE IF NOT EXISTS users (" +
		"name VARCHAR(64) PRIMARY KEY, " +
		"salt VARCHAR(128) NULL, " +
		"pass VARCHAR(128) NULL, " +
		"gid VARCHAR(64) NULL, " +
		"umask VARCHAR(4) NULL, " +
		"FOREIGN KEY (gid) REFERENCES groups(name)" +
		");")

}

func (p *Privileges) createUsersGroupsTable() {

	p.db.Exec("CREATE TABLE IF NOT EXISTS usersgroups (" +
		"username VARCHAR(64) NULL, " +
		"groupname VARCHAR(64) NULL, " +
		"PRIMARY KEY (username, groupname), " +
		"FOREIGN KEY (username) REFERENCES users(name) ON DELETE CASCADE, " +
		"FOREIGN KEY (groupname) REFERENCES groups(name) ON DELETE CASCADE" +
		");")

}

func (p *Privileges) createStandardEntries() {

	p.newUser(root, rootPassword)

}

func (p *Privileges) newGroup(name string) error {

	if name == "" {
		return errBadName
	}

	_, err := p.db.Exec("INSERT INTO groups(name) VALUES(?)", name)
	return err

}

func (p *Privileges) newUser(username, password string) error {

	if username == "" {
		return errBadName
	}

	err := p.newGroup(username)
	if err != nil {
		return err
	}

	salt, hash := saltAndHash(password)
	p.db.Exec("INSERT INTO users(name, salt, pass, gid, umask) VALUES(?, ?, ?, ?, ?)", username, salt, hash, username, "0002")
	p.addToGroup(username, username)
	return nil

}

func (p *Privileges) newUserHash(username, salt, hash string) error {

	if username == "" {
		return errBadName
	}

	if len(salt) != 64 {
		return errBadSalt
	}

	if len(hash) != 64 {
		return errBadHash
	}

	err := p.newGroup(username)
	if err != nil {
		return err
	}

	p.db.Exec("INSERT INTO users(name, salt, pass, gid, umask) VALUES(?, ?, ?, ?, ?)", username, salt, hash, username, "0002")
	p.addToGroup(username, username)
	return nil

}

func (p *Privileges) changePassword(username, salt, hashword string) error {

	row := p.db.QueryRow("SELECT * FROM users WHERE name=?", username)
	rec := new(record)
	err := row.Scan(&rec.name, &rec.salt, &rec.pass, &rec.gid, &rec.umask)
	if err != nil {
		return err
	}

	if len(salt) != 64 {
		return errBadSalt
	}

	if len(hashword) != 64 {
		return errBadHash
	}

	_, err = p.db.Exec("UPDATE users SET salt=?, pass=? WHERE name=?", salt, hash, username)
	return err

}

func (p *Privileges) addToGroup(user, group string) error {

	_, err := p.db.Exec("INSERT INTO usersgroups(username, groupname) VALUES(?, ?)", user, group)
	return err

}

func (p *Privileges) inGroup(username, group string) (bool, error) {

	var x string
	row := p.db.QueryRow("SELECT * FROM usersgroups WHERE username=? AND groupname=?", username, group)
	err := row.Scan(&x, &x)
	return err == nil, err

}

func (p *Privileges) userListGroups(username string) ([]string, error) {

	var groups []string

	rows, err := p.db.Query("SELECT groupname FROM usersgroups WHERE username=?", username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var name string
	for rows.Next() {
		rows.Scan(&name)
		groups = append(groups, name)
	}

	return groups, nil

}

func (p *Privileges) deleteUser(username string) error {

	if username == root {
		return errRoot
	}

	_, err := p.db.Exec("DELETE FROM users WHERE name=?", username)
	return err

}

func (p *Privileges) deleteGroup(group string) error {

	if group == root {
		return errRoot
	}

	users, err := p.listUsersWithGid(group)
	if err != nil {
		return err
	}
	if users != nil && len(users) != 0 {
		return errGroupHasGids
	}

	_, err = p.db.Exec("DELETE FROM groups WHERE name=?", group)
	return err

}

func (p *Privileges) listUsersWithGid(group string) ([]string, error) {

	var users []string

	rows, err := p.db.Query("SELECT name FROM users WHERE gid=?", group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var user string
	for rows.Next() {
		rows.Scan(&user)
		users = append(users, user)
	}

	return users, nil

}

func (p *Privileges) setGid(username, group string) error {

	_, err := p.db.Exec("UPDATE users SET gid=? WHERE name=?", group, username)
	return err

}

func (p *Privileges) gid(username string) (string, error) {

	var gid string
	row := p.db.QueryRow("SELECT gid FROM users WHERE name=?", username)
	err := row.Scan(&gid)
	return gid, err

}

func (p *Privileges) setUmask(mask, username string) error {

	if !validRules(mask) {
		return errBadRulesString
	}

	_, err := p.db.Exec("UPDATE users SET umask=? WHERE name=?", mask, username)
	return err

}

func (p *Privileges) removeFromGroup(user, group string) error {

	_, err := p.db.Exec("DELETE FROM usersgroups WHERE username=? AND groupname=?", user, group)
	return err

}

func (p *Privileges) listGroups() ([]string, error) {

	var groups []string

	rows, err := p.db.Query("SELECT name FROM groups")
	if err != nil {
		return nil, err
	}

	var name string
	for rows.Next() {
		rows.Scan(&name)
		groups = append(groups, name)
	}

	return groups, nil

}

func (p *Privileges) listUsers() ([]string, error) {

	var users []string

	rows, err := p.db.Query("SELECT name FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var name string
	for rows.Next() {
		rows.Scan(&name)
		users = append(users, name)
	}

	return users, nil

}
