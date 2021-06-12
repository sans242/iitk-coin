package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	DB *sql.DB
}

func hashAndSalt(pwd []byte) string {

	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

var a = &App{}
var mySigningKey = []byte("scott")

type User struct {
	Username string `json:"username"`
	Rollno   int    `json:"rollno"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type userlogin struct {
	Rollno   int    `json:"rollno"`
	Password string `json:"password"`
}

func GetJWT(username string, rollno int, name string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["username"] = username
	claims["rollno"] = rollno
	claims["name"] = name
	claims["exp"] = time.Now().Add(time.Minute * 60).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		fmt.Errorf("Something Went Wrong: %s", err.Error())
		return "", err
	}

	return tokenString, nil
}

func comparePasswords(hashedPwd string, plainPwd []byte) bool {
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func signup(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	body, err := ioutil.ReadAll(req.Body)
	//fmt.Println(string(body))
	if err != nil {
		panic(err)
	}
	var user User
	json.Unmarshal([]byte(string(body)), &user)
	//fmt.Println(user.Username)
	passkey := hashAndSalt([]byte(user.Password))
	//fmt.Println(passkey)
	data, _ := a.DB.Begin()
	//fmt.Println(data)
	statement, _ := data.Prepare("INSERT INTO user (username, rollno, name, password) VALUES (?, ?, ?, ?) ")
	//fmt.Println(statement)
	_, error := statement.Exec(user.Username, user.Rollno, user.Name, passkey)
	if err != nil {
		fmt.Println(error)
	}

	data.Commit()

}

func login(rw http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	body, err := ioutil.ReadAll(req.Body)
	//fmt.Println(string(body))
	if err != nil {
		panic(err)
	}
	var user userlogin
	json.Unmarshal([]byte(string(body)), &user)
	//fmt.Println(user.Rollno)
	rows, _ := a.DB.Query("SELECT id, username, name, rollno, password FROM user")

	var id int
	var username string
	var rollno string
	var name string
	var password string

	for rows.Next() {
		rows.Scan(&id, &username, &name, &rollno, &password)
		rollnos, _ := strconv.Atoi(rollno)
		//fmt.Println(strconv.Itoa(id) + ": " + rollno + " " + name + " " + password + " " + username)
		//fmt.Println(rollnos)

		if rollnos == user.Rollno {
			pwd_matches := comparePasswords(password, []byte(user.Password))
			if pwd_matches {
				validToken, _ := GetJWT(username, rollnos, name)

				fmt.Println(validToken)
			}
		}
	}
}

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Super Secret Information")
}

func isAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header["Token"] != nil {

			token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf(("Invalid Signing Method"))
				}
				aud := "billing.jwtgo.io"
				checkAudience := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
				if !checkAudience {
					return nil, fmt.Errorf(("invalid aud"))
				}
				// verify iss claim
				iss := "jwtgo.io"
				checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
				if !checkIss {
					return nil, fmt.Errorf(("invalid iss"))
				}

				return mySigningKey, nil
			})
			if err != nil {
				fmt.Fprintf(w, err.Error())
			}

			if token.Valid {
				endpoint(w, r)
			}

		} else {
			fmt.Fprintf(w, "No Authorization Token provided")
		}
	})
}

func main() {
	database, _ := sql.Open("sqlite3", "./userdata.db")
	a.DB = database
	statement, _ := database.Prepare("CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY,username TEXT, rollno INTEGER, name TEXT, password TEXT)")
	statement.Exec()

	/*rows, _ := database.Query("SELECT id, rollno, name FROM user")
	var id int
	var rollno int
	var name string
	for rows.Next() {
		rows.Scan(&id, &rollno, &name)
		fmt.Println(strconv.Itoa(id) + ": " + strconv.Itoa(rollno) + " " + name)
	}*/
	rows, _ := a.DB.Query("SELECT id, username, name, rollno, password FROM user")

	var id int
	var username string
	var rollno string
	var name string
	var password string

	for rows.Next() {
		rows.Scan(&id, &username, &name, &rollno, &password)

		fmt.Println(strconv.Itoa(id) + ": " + rollno + " " + name + " " + password + " " + username)
	}

	http.HandleFunc("/login", login)
	http.Handle("/secretpage", isAuthorized(homePage))
	http.HandleFunc("/signup", signup)

	fmt.Printf("Starting server at port 8080\n")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
