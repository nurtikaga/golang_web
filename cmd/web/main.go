// main.go
package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/gorilla/mux"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID             int    `json:"id"`
	FullName       string `json:"name"`
	Email          string `json:"email" gorm:"unique"`
	HashedPassword string `json:"-"`
	Role           string `json:"role"`
}

var jwtKey = []byte("secret")

type Claims struct {
	UserID int    `json:"user_id"`
	Role   string `json:"role"`
	jwt.StandardClaims
}

type Article struct {
	Id                     uint16
	Title, Anons, FullText string
}
type Comments struct {
	Id                     uint16
	user_id, news_id, text string
}
type Departments struct {
	ID            int
	DepName       string
	StaffQuantity int
}
type Deletedarticle struct {
	Id                     uint16
	Title, Anons, FullText string
}

var posts = []Article{}
var showPost = Article{}
var showComments = Comments{}
var deleted = []Deletedarticle{}
var deletedPost = Deletedarticle{}

// exported

func index(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles(
		"/Users/nurtileu/Documents/snippetbox/ui/static/index.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/register/register.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/header.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/footer.html")

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/golang")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	res, err := db.Query("SELECT * FROM `articles`")
	if err != nil {
		panic(err)
	}
	posts = []Article{}
	for res.Next() {
		var post Article
		err = res.Scan(&post.Id, &post.Title, &post.Anons, &post.FullText)
		if err != nil {
			panic(err)
		}
		posts = append(posts, post)
	}
	successMessage := r.URL.Query().Get("success")
	data := struct {
		Posts          []Article
		SuccessMessage string
	}{
		Posts:          posts,
		SuccessMessage: successMessage,
	}

	// Execute the template with the data
	t.ExecuteTemplate(w, "index", data)
}

// exported
func create(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles(
		"/Users/nurtileu/Documents/snippetbox/ui/static/create.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/header.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/footer.html")

	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	t.ExecuteTemplate(w, "create", nil)
}

// exported
func show_post(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	t, err := template.ParseFiles(
		"/Users/nurtileu/Documents/snippetbox/ui/static/show.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/header.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/footer.html")

	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/golang")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	res, err := db.Query(fmt.Sprintf("SELECT * FROM `articles` WHERE `id` = '%s'", vars["id"]))
	if err != nil {
		panic(err)
	}
	showPost = Article{}
	for res.Next() {
		var post Article
		err = res.Scan(&post.Id, &post.Title, &post.Anons, &post.FullText)
		if err != nil {
			panic(err)
		}
		showPost = post
	}

	res, err2 := db.Query(fmt.Sprintf("SELECT * FROM `comments` WHERE `id` = '%s'", vars["id"]))
	if err2 != nil {
		panic(err2)
	}
	showComments = Comments{}
	for res.Next() {
		var post Comments
		err = res.Scan(&post.Id, &post.news_id, &post.user_id, &post.text)
		if err != nil {
			panic(err)
		}
		showComments = post
	}
	t.ExecuteTemplate(w, "show", showPost)
}

// exported
func home(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles(
		"/Users/nurtileu/Documents/snippetbox/ui/static/index.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/header.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/footer.html")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	t.ExecuteTemplate(w, "index", posts)
}

// exported
func contacts(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles(
		"/Users/nurtileu/Documents/snippetbox/ui/static/contacts.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/header.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/footer.html")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	t.ExecuteTemplate(w, "contacts", nil)
}

// exporteds
func aboutUs(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles(
		"/Users/nurtileu/Documents/snippetbox/ui/static/index.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/header.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/footer.html")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	t.ExecuteTemplate(w, "index", posts)
}
func departments(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles(
		"/Users/nurtileu/Documents/snippetbox/ui/static/departments.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/header.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/footer.html")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	t.ExecuteTemplate(w, "departments", nil)
}
func savezayava(w http.ResponseWriter, r *http.Request) {
	dep_name := r.FormValue("dep_name")
	staff_quantity := r.FormValue("staff_quantity")

	if dep_name == "" || staff_quantity == "" {
		fmt.Fprintf(w, "Ne vse zapolneny")
	}
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/departments")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	insert, err := db.Query(fmt.Sprintf("INSERT INTO `departments` (`dep_name`, `staff_quantity`) VALUES('%s', '%s')", dep_name, staff_quantity))

	if err != nil {
		panic(err)
	}
	defer insert.Close()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func deletePost(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	t, err := template.ParseFiles(
		"/Users/nurtileu/Documents/snippetbox/ui/static/deleted.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/header.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/footer.html")

	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/golang")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	delete, err := db.Query(fmt.Sprintf("DELETE FROM articles WHERE `id` = '%s'", vars["id"]))
	if err != nil {
		panic(err)
	}

	deletedPost = Deletedarticle{}
	for delete.Next() {
		var post Deletedarticle
		err = delete.Scan(&post.Id, &post.Title, &post.Anons, &post.FullText)
		if err != nil {
			panic(err)
		}
		deletedPost = post
	}
	t.ExecuteTemplate(w, "deleted", http.StatusSeeOther)
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles(
		"/Users/nurtileu/Documents/snippetbox/ui/static/login/login.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/header.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/footer.html")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	t.ExecuteTemplate(w, "login", map[string]interface{}{"ErrorMessage": ""})
}

func registerPage(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles(
		"/Users/nurtileu/Documents/snippetbox/ui/static/register/register.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/header.html",
		"/Users/nurtileu/Documents/snippetbox/ui/static/footer.html")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	t.ExecuteTemplate(w, "register", posts)
}

func register(w http.ResponseWriter, r *http.Request) {
	// Parse the form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	fullName := r.FormValue("full_name")
	email := r.FormValue("email")
	password := r.FormValue("password")
	role := r.FormValue("role")
	// Hash the password before saving to the database
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Unable to hash password", http.StatusInternalServerError)
		return
	}
	// Save the user to the database
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/golang")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer db.Close()

	insert, err := db.Query(fmt.Sprintf("INSERT INTO `users` (`full_name`, `email`, `hashed_password`, `role`) VALUES('%s', '%s', '%s', '%s')", fullName, email, hashedPassword, role))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer insert.Close()

	// Redirect or respond as needed
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Replace this with your actual authentication logic
// Replace the authenticateUser function
func authenticateUser(email, password string) (uint64, string, error) {
	// Retrieve the user by email
	user, err := getUserByEmail(email)
	if err != nil {
		return 0, "", err
	}

	// Compare the hashed password
	err = bcrypt.CompareHashAndPassword([]byte(user.HashedPassword), []byte(password))
	if err != nil {
		return 0, "", err
	}

	// Authentication successful, return user ID and role
	return uint64(user.ID), user.Role, nil
}

// Create a JWT token with user claims
func createToken(userID int, role string) (string, error) {
	// Create a new Claims struct with user ID and role
	claims := &Claims{
		UserID: userID,
		Role:   role,
		// Add other claims as needed
	}

	// Create a new JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with your secret key
	signedToken, err := token.SignedString([]byte("your-secret-key"))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	// Parse the login form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error parsing form data", http.StatusBadRequest)
		return
	}

	// Retrieve the email and password from the form
	email := r.Form.Get("email")
	password := r.Form.Get("pass")

	// Authenticate the user
	userID, role, err := authenticateUser(email, password)
	if err != nil {
		t, err := template.ParseFiles(
			"/Users/nurtileu/Documents/snippetbox/ui/static/login/login.html",
			"/Users/nurtileu/Documents/snippetbox/ui/static/header.html",
			"/Users/nurtileu/Documents/snippetbox/ui/static/footer.html")
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		errorMessage := "Login or password is not correct"
		t.ExecuteTemplate(w, "login", map[string]interface{}{"ErrorMessage": errorMessage})
		return
	} else {
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}

	// Create a JWT token with user claims
	token, err := createToken(int(userID), role)
	if err != nil {
		http.Error(w, "Error creating JWT token", http.StatusInternalServerError)
		return
	}

	// Set the token in the response header or cookie
	// For example, setting it in the response header:
	w.Header().Set("Authorization", "Bearer "+token)

	http.SetCookie(w, &http.Cookie{
		Name:  "user_token",
		Value: role, // Set the user's role
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ...

// getUserByEmail retrieves a user from the database based on the email.
func getUserByEmail(email string) (*User, error) {
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/golang")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var user User
	err = db.QueryRow("SELECT * FROM `users` WHERE `email` = ?", email).Scan(&user.ID, &user.FullName, &user.Email, &user.HashedPassword, &user.Role)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Function to verify a JWT token
func verifyToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// Modify the save_article function
func save_article(w http.ResponseWriter, r *http.Request) {
	title := r.FormValue("title")
	anons := r.FormValue("anons")
	full_text := r.FormValue("full_text")
	// Parse the form data
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if title == "" || anons == "" || full_text == "" {
		fmt.Fprintf(w, "Ne vse zapolneny")
	}
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/golang")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	insert, err := db.Query(fmt.Sprintf("INSERT INTO `articles` (`title`, `anons`, `full_text`) VALUES('%s', '%s', '%s')", title, anons, full_text))

	if err != nil {
		panic(err)
	}
	defer insert.Close()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Modify the checkRole middleware
func checkRole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Retrieve the user's ID from the token
		tokenString := r.URL.Query().Get("token")
		if tokenString == "" {
			http.Error(w, "Token missing", http.StatusUnauthorized)
			return
		}

		claims, err := verifyToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Check the user's role
		if claims.Role != "student" {
			// Only students can access certain routes, modify as needed
			http.Error(w, "Access forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func save_comment(w http.ResponseWriter, r *http.Request) {
	C1 := r.FormValue("c1")
	C2 := r.FormValue("c2")
	C3 := r.FormValue("c3")
	C4 := r.FormValue("c4")
	if C1 == "" || C2 == "" || C3 == "" || C4 == "" {
		fmt.Fprintf(w, "Ne vse zapolneny")
	}
	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/golang")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	insert, err := db.Query(fmt.Sprintf("INSERT INTO `comments` (`id`, `user_id`, `news_id`, `text`) VALUES('%s', '%s', '%s', '%s')", C1, C2, C3, C4))

	if err != nil {
		panic(err)
	}
	defer insert.Close()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleFunc() {
	rtr := mux.NewRouter()
	rtr.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("/Users/nurtileu/Documents/snippetbox/ui/static"))))
	rtr.HandleFunc("/", index).Methods("GET")
	rtr.HandleFunc("/create", create).Methods("GET")
	rtr.HandleFunc("/save_article", save_article).Methods("POST")
	rtr.HandleFunc("/post/{id:[0-9]+}", show_post).Methods("GET")
	rtr.HandleFunc("/home", home).Methods("GET").Queries("token", "{token}").Subrouter().Use(checkRole)
	rtr.HandleFunc("/contacts", contacts).Methods("GET")
	rtr.HandleFunc("/aboutus", aboutUs).Methods("GET")
	rtr.HandleFunc("/departments", departments).Methods("GET")
	rtr.HandleFunc("/savezayava", savezayava).Methods("POST")
	rtr.HandleFunc("/deletePost/{id:[0-9]+}", deletePost)

	// Registration routes
	rtr.HandleFunc("/register", registerPage).Methods("GET")
	rtr.PathPrefix("/register/").Handler(http.StripPrefix("/register/", http.FileServer(http.Dir("/Users/nurtileu/Documents/snippetbox/ui/static/register"))))
	rtr.HandleFunc("/register", register).Methods("POST")

	// Login routes
	rtr.HandleFunc("/login", loginPage).Methods("GET")
	rtr.HandleFunc("/login", login).Methods("POST")
	rtr.PathPrefix("/login/").Handler(http.StripPrefix("/login/", http.FileServer(http.Dir("/Users/nurtileu/Documents/snippetbox/ui/static/login"))))

	//Leave comments
	//save_comment
	rtr.HandleFunc("/save_comment", save_comment).Methods("POST")
	//rtr.HandleFunc("/post/{id:[0-9]+}", show_comment).Methods("GET")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./ui/static/index.html")
	})

	http.ListenAndServe(":5501", nil)

}

func main() {
	handleFunc()
}
