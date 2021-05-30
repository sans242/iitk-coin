package main

import (
	"database/sql"
	"fmt"
	"strconv"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	database, _ := sql.Open("sqlite3", "./userdata.db")
	statement, _ := database.Prepare("CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY, rollno INTEGER, name TEXT)")
	statement.Exec()
	statement, _ = database.Prepare("INSERT INTO user (rollno, name) VALUES (?, ?) ")
	statement.Exec(100, "Scott")

	rows, _ := database.Query("SELECT id, rollno, name FROM user")
	var id int
	var rollno int
	var name string
	for rows.Next() {
		rows.Scan(&id, &rollno, &name)
		fmt.Println(strconv.Itoa(id) + ": " + strconv.Itoa(rollno) + " " + name)
	}
}
