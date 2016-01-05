package privileges

import (
	"crypto/rand"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"

	// driver for sqlite3
	sqlite3 "github.com/mattn/go-sqlite3"
)

const (
	rootName  = "root"
	rootPass  = "guest"
	rootGroup = "sudo"
)

func init() {
	sql.Register("sqlite3_with_foreign_keys",
		&sqlite3.SQLiteDriver{
			ConnectHook: func(conn *sqlite3.SQLiteConn) error {
				_, err := conn.Exec("PRAGMA foreign_keys = ON", nil)
				return err
			},
		})
}

func loadDatabase(path string) (*Privileges, error) {

	p := new(Privileges)
	p.path = path
	p.db, _ = sql.Open("sqlite3_with_foreign_keys", p.path)
	p.setup()
	return p, nil

}

func (p *Privileges) setup() {

	p.createGroupsTable()
	p.createUsersTable()
	p.createUsersGroupsTable()
	p.createStandardEntries()

}

func (p *Privileges) createGroupsTable() {

	p.db.Exec("CREATE TABLE IF NOT EXISTS groups (" +
		"name VARCHAR(64) PRIMARY KEY);")

}

func (p *Privileges) createUsersTable() {

	p.db.Exec("CREATE TABLE IF NOT EXISTS users (" +
		"name VARCHAR(64) PRIMARY KEY, " +
		"salt VARCHAR(128) NULL, " +
		"pass VARCHAR(128) NULL, " +
		"gid VARCHAR(64) NULL, " +
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

	p.newGroup(rootGroup)
	p.newUser(rootName, rootPass)
	p.addToGroup(rootName, rootGroup)

}

func (p *Privileges) login(user *Key, password string) error {

	var username, salt, pass, gid string
	row := p.db.QueryRow("SELECT * FROM users WHERE name=?", user.username)
	err := row.Scan(&username, &salt, &pass, &gid)
	if err != nil {
		return errors.New("invalid username or password")
	}

	user.hashword, err = hash(salt, password)
	if err != nil || user.hashword != pass {
		return errors.New("invalid username or password")
	}

	return nil

}

func (p *Privileges) newGroup(name string) error {

	_, err := p.db.Exec("INSERT INTO groups(name) VALUES(?)", name)
	return err

}

func (p *Privileges) newUser(username, password string) error {

	p.newGroup(username)
	salt, hash := saltAndHash(password)
	_, err := p.db.Exec("INSERT INTO users(name, salt, pass, gid) VALUES(?, ?, ?, ?)", username, salt, hash, username)
	return err

}

func (p *Privileges) addToGroup(user, group string) error {

	_, err := p.db.Exec("INSERT INTO usersgroups(username, groupname) VALUES(?, ?)", user, group)
	return err

}

func (p *Privileges) inGroup(username, group string) bool {

	var x string
	row := p.db.QueryRow("SELECT * FROM usersgroups WHERE username=? AND groupname=?", username, group)
	err := row.Scan(&x, &x)
	return err == nil

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

func (key *Key) valid() bool {

	var user, salt, pass, gid string
	row := key.p.db.QueryRow("SELECT * FROM users WHERE name=?", key.username)
	err := row.Scan(&user, &salt, &pass, &gid)
	if err != nil {
		return false
	}

	if pass == key.hashword {
		return true
	}

	return false

}

func (key *Key) su() bool {

	return key.p.inGroup(key.username, rootGroup)

}

func (p *Privileges) isGroup(group string) bool {

	var x string
	row := p.db.QueryRow("SELECT name FROM groups WHERE name=?", group)
	err := row.Scan(&x)
	return err == nil

}

func (p *Privileges) isUser(username string) bool {

	var x string
	row := p.db.QueryRow("SELECT name FROM users WHERE name=?", username)
	err := row.Scan(&x)
	return err == nil

}

func (p *Privileges) listGroups() []string {

	var groups []string

	rows, err := p.db.Query("SELECT name FROM groups")
	if err != nil {
		return nil
	}

	var name string
	for rows.Next() {
		rows.Scan(&name)
		groups = append(groups, name)
	}

	return groups

}

func (p *Privileges) listUsers() []string {

	var users []string

	rows, err := p.db.Query("SELECT name FROM users")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var name string
	for rows.Next() {
		rows.Scan(&name)
		users = append(users, name)
	}

	return users

}

func (p *Privileges) listUsersGroups(user string) []string {

	var groups []string

	rows, err := p.db.Query("SELECT groupname FROM usersgroups WHERE username=?", user)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var name string
	for rows.Next() {
		rows.Scan(&name)
		groups = append(groups, name)
	}

	return groups

}

func (p *Privileges) listUsersWithGid(group string) []string {

	var users []string

	rows, err := p.db.Query("SELECT name FROM users WHERE gid=?", group)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var user string
	for rows.Next() {
		rows.Scan(&user)
		users = append(users, user)
	}

	return users

}

func (p *Privileges) deleteUser(username string) error {

	_, err := p.db.Exec("DELETE FROM users WHERE name=?", username)
	return err

}

func (p *Privileges) deleteGroup(group string) error {

	_, err := p.db.Exec("DELETE FROM groups WHERE name=?", group)
	return err

}

func (p *Privileges) removeFromGroup(user, group string) error {

	_, err := p.db.Exec("DELETE FROM usersgroups WHERE username=? AND groupname=?", user, group)
	return err

}

func (p *Privileges) changePassword(username, password string) error {

	salt, hash := saltAndHash(password)

	_, err := p.db.Exec("UPDATE users SET salt=?, pass=? WHERE name=?", salt, hash, username)
	return err

}

func (p *Privileges) setGid(username, group string) error {

	_, err := p.db.Exec("UPDATE users SET gid=? WHERE name=?", group, username)
	return err

}

func (p *Privileges) gid(username string) string {

	var gid string
	row := p.db.QueryRow("SELECT gid FROM users WHERE name=?", username)
	row.Scan(&gid)
	return gid

}

func (p *Privileges) close() {
	p.db.Close()
}

func (p *Privileges) Restore(path string) error {

	p.close()

	err := os.Rename(path, p.path)
	if err != nil {
		return err
	}

	p.db, _ = sql.Open("sqlite3_with_foreign_keys", p.path)

	return nil

}

func (p *Privileges) Snapshot() ([]byte, error) {

	return ioutil.ReadFile(p.path)

}
