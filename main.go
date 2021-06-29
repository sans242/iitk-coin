package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type App struct {
	DB            *sql.DB
	transactiondb *sql.DB
}

func hashAndSalt(pwd []byte) string {

	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

var lock sync.Mutex
var a = &App{}
var mySigningKey = []byte("scott")

type User struct {
	Username                 string `json:"username"`
	Rollno                   int    `json:"rollno"`
	Name                     string `json:"name"`
	Password                 string `json:"password"`
	Coins                    int    `json:"coins"`
	PermissionsLevel         int    `json:"permissions"`
	CompetitionsParticipated int    `json:"competitionsParticipated"`
}

type userlogin struct {
	Rollno   int    `json:"rollno"`
	Password string `json:"password"`
}

type RetrieveBalance struct {
	Rollno int `json:"rollno"`
	Coins  int `json:"coins"`
}

type UpdateCoins struct {
	Rollno int `json:"rollno"`
	Coins  int `json:"coins"`
}

type TransferCoins struct {
	SenderRollno   int `json:"senderRollno"`
	ReceiverRollno int `json:"receiverRollno"`
	SenderCoins    int `json:"senderCoins"`
	ReceiverCoins  int `json:"receiverCoins"`
	Coins          int `json:"transferCoins"`
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
	user.Coins = 0
	user.PermissionsLevel = 0
	user.CompetitionsParticipated = 0
	if user.Rollno == 999999 {
		user.PermissionsLevel = 2
	}
	passkey := hashAndSalt([]byte(user.Password))
	//fmt.Println(passkey)
	data, _ := a.DB.Begin()
	//fmt.Println(data)
	statement, _ := data.Prepare("INSERT INTO user (username, name, rollno, password, coins, permissionLevel, competitionsParticipated) VALUES (?, ?, ?, ?, ?, ?, ?)")
	demo, err := statement.Exec(user.Username, user.Name, user.Rollno, passkey, user.Coins, user.PermissionsLevel, user.CompetitionsParticipated)

	fmt.Println(demo)

	if err != nil {
		fmt.Println(err)
	}

	data.Commit()
	fmt.Println("USER CREATED HURRAY!!!")

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

func ExtractClaims(tokenStr string) (jwt.MapClaims, bool) {
	// hmacSecretString := // Value
	hmacSecret := mySigningKey
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// check token signing method etc
		return hmacSecret, nil
	})

	if err != nil {
		return nil, false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, true
	} else {
		log.Printf("Invalid JWT Token")
		return nil, false
	}
}

func GetUserPermission(db *sql.DB, rollno int) int {
	query := db.QueryRow("select permissionLevel from user where rollno=$1", rollno)
	var id int
	query.Scan(&id)

	return id
}

func GetNumCompetiton(db *sql.DB, rollno int) int {
	query := db.QueryRow("select competitionsParticipated from user where rollno=$1", rollno)
	var id int
	query.Scan(&id)

	return id
}

func UpdateNumCompetitions(db *sql.DB, id int, rollno int, competitions int) bool {
	sid := strconv.Itoa(id)
	scompetitions := strconv.Itoa(competitions)
	// srollno := strconv.Itoa(rollno)
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("update user set competitionsParticipated=? where id=?")
	_, err := stmt.Exec(scompetitions, sid)
	if err != nil {
		fmt.Println(err)
		return false
	}
	tx.Commit()

	return true
}

func getbal(w http.ResponseWriter, r *http.Request) {
	lock.Lock()
	defer lock.Unlock()

	time.Sleep(1 * time.Second)

	r.ParseForm()
	w.Header().Set("Content-Type", "application/json")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var user UpdateCoins
	json.Unmarshal([]byte(string(body)), &user)
	claims, status1 := ExtractClaims(r.Header["Token"][0])
	if status1 {
		permission := GetUserPermission(a.DB, int(claims["rollno"].(float64)))

		if permission == 2 {
			userId := GetUserId(a.DB, user.Rollno)

			if userId == 0 {
				fmt.Println("No such user present!")
				return
			}

			currentCoins := GetCoins(a.DB, user.Rollno)
			numCompetiton := GetNumCompetiton(a.DB, user.Rollno)

			status := UpdateUser(a.DB, userId, user.Rollno, user.Coins+currentCoins)
			numCompetiton = numCompetiton + 1
			status2 := UpdateNumCompetitions(a.DB, userId, user.Rollno, numCompetiton)
			status3 := AddTransaction(a.transactiondb, "add", user.Rollno, int(claims["rollno"].(float64)), user.Coins, time.Now().String())

			if status && status2 && status3 {
				fmt.Println("Coins given Successfully!")
			} else {
				fmt.Println("Error in giving coins, please try again!")
			}
		} else {
			fmt.Println("You are not authorized to give Coins!")
		}
	} else {
		fmt.Println("Please re-login and try again!")
	}

	/*currentCoins := GetCoins(a.DB, user.Rollno)
	userId := GetUserId(a.DB, user.Rollno)

	if userId == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println("user not present here!!!")

		return
	}

	status := UpdateUser(a.DB, userId, user.Rollno, user.Coins+currentCoins)

	if status {
		fmt.Println("Coins given!!!")
		return
	}

	/*else {
	    fmt.Println("Error in giving coins, please try again!")
	}*/
}

func AddTransaction(db *sql.DB, typeOfTransaction string, transferToRollno int, senderRollNo int, coins int, timestamp string) bool {
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("INSERT INTO transactionHistory (typeOfTransaction, transferToRollno, senderRollNo, coins, timestamp) VALUES (?, ?, ?, ?, ?)")
	_, err := stmt.Exec(typeOfTransaction, transferToRollno, senderRollNo, coins, timestamp)
	if err != nil {
		fmt.Println(err)
		return false
	}
	tx.Commit()

	return true
}

func transfer(w http.ResponseWriter, r *http.Request) {
	lock.Lock()
	defer lock.Unlock()

	time.Sleep(1 * time.Second)

	r.ParseForm()
	w.Header().Set("Content-Type", "application/json")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var user TransferCoins
	json.Unmarshal([]byte(string(body)), &user)
	fmt.Println(user)

	senderUser := GetUserId(a.DB, user.SenderRollno)
	receiverUser := GetUserId(a.DB, user.ReceiverRollno)

	if senderUser == 0 {
		fmt.Println("no such user to send present!!!")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if receiverUser == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println("No such user to receive present!!!")

		return
	}

	numCompetiton := GetNumCompetiton(a.DB, user.ReceiverRollno)
	if numCompetiton == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println("Ineligible User")

		return
	}

	senderCoins := GetCoins(a.DB, user.SenderRollno)
	receiverCoins := GetCoins(a.DB, user.ReceiverRollno)

	if senderCoins >= user.Coins {
		var coins float64 = float64(user.Coins)
		diff := user.SenderRollno/10000 - user.ReceiverRollno/10000

		if math.Abs(float64(diff)) > 0 {
			coins = (coins * 2) / 3
		} else if math.Abs(float64(diff)) == 0 {
			coins = (coins * 49) / 50
		}

		status1 := UpdateUser(a.DB, senderUser, user.SenderRollno, senderCoins-user.Coins)
		status2 := UpdateUser(a.DB, receiverUser, user.ReceiverRollno, receiverCoins+int(coins))

		if status1 && status2 {
			AddTransaction(a.transactiondb, "transfer", user.ReceiverRollno, user.SenderRollno, user.Coins, time.Now().String())
			fmt.Println("Transfer successful!!!")

			return
		} else {
			if status1 && !status2 {
				UpdateUser(a.DB, senderUser, user.SenderRollno, senderCoins+user.Coins)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Println("Transfer error!!!")
				return
			} else if !status1 && status2 {
				UpdateUser(a.DB, senderUser, user.SenderRollno, receiverCoins-user.Coins)
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Println("Transfer error!!!")
				return
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Println("Transfer Error!!!")

				return
			}
		}

	} else {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Println("Insufficient Balance!!!")

		return
	}
}

func balance(w http.ResponseWriter, r *http.Request) {
	lock.Lock()
	defer lock.Unlock()

	time.Sleep(time.Millisecond)

	r.ParseForm()
	w.Header().Set("Content-Type", "application/json")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	var user RetrieveBalance
	json.Unmarshal([]byte(string(body)), &user)

	userId := GetUserId(a.DB, user.Rollno)

	if userId == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println("User not present!!!")

		return
	}

	response := RetrieveBalance{
		Rollno: user.Rollno,
		Coins:  GetCoins(a.DB, user.Rollno),
	}
	json.NewEncoder(w).Encode(response)
}

func UpdateUser(db *sql.DB, id int, rollno int, coins int) bool {
	sid := strconv.Itoa(id)
	scoins := strconv.Itoa(coins)
	// srollno := strconv.Itoa(rollno)
	tx, _ := db.Begin()
	stmt, _ := tx.Prepare("update user set coins=? where id=?")
	_, err := stmt.Exec(scoins, sid)
	if err != nil {
		fmt.Println(err)
		return false
	}
	tx.Commit()

	return true
}

func GetCoins(db *sql.DB, rollno int) int {
	query := db.QueryRow("select coins from user where rollno=$1", rollno)
	var coins int
	query.Scan(&coins)

	return coins
}

func GetUserId(db *sql.DB, rollno int) int {
	query := db.QueryRow("select id from user where rollno=$1", rollno)
	var id int
	query.Scan(&id)

	return id
}

func main() {
	database, _ := sql.Open("sqlite3", "./userdata.db")
	a.DB = database
	statement, _ := database.Prepare("CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY,username TEXT, name TEXT, rollno INTEGER, password TEXT, coins INTEGER, permissionLevel INTEGER, competitionsParticipated INTEGER)")
	statement.Exec()
	db, _ := sql.Open("sqlite3", "./transactionHistory.db")
	a.transactiondb = db
	statement1, _ := db.Prepare("CREATE TABLE IF NOT EXISTS transactionHistory (id INTEGER PRIMARY KEY, typeOfTransaction TEXT, transferToRollno INTEGER, senderRollNo INTEGER, coins INTEGER, timestamp TEXT)")
	statement1.Exec()

	/*rows, _ := database.Query("SELECT id, rollno, name FROM user")
	var id int
	var rollno int
	var name string
	for rows.Next() {
		rows.Scan(&id, &rollno, &name)
		fmt.Println(strconv.Itoa(id) + ": " + strconv.Itoa(rollno) + " " + name)
	}*/
	rows, _ := a.DB.Query("SELECT id, username, name, rollno, password, coins FROM user")

	var id int
	var username string
	var rollno string
	var name string
	var password string
	var coins string

	for rows.Next() {
		rows.Scan(&id, &username, &name, &rollno, &password, &coins)

		fmt.Println(strconv.Itoa(id) + ": " + rollno + " " + name + " " + password + " " + username + " " + coins)
	}

	http.HandleFunc("/login", login)
	http.Handle("/secretpage", isAuthorized(homePage))
	http.HandleFunc("/signup", signup)
	http.Handle("/initialise", isAuthorized(getbal))
	http.Handle("/transfer", isAuthorized(transfer))
	http.Handle("/balance", isAuthorized(balance))

	fmt.Printf("Starting server at port 8080\n")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
