package main

import (
	"database/sql"
	"fmt"
	"html"
	"html/template"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
)

type Filter struct{ Name string }

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	id := mux.Vars(r)["id"]
	q := r.URL.Query().Get("q")

	// ruleid: vulnscan.go.sql-injection
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	// ruleid: vulnscan.go.sql-injection
	db.QueryRow(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
	// ok: vulnscan.go.sql-injection
	db.Query("SELECT * FROM users WHERE name = ?", name)
	n, _ := strconv.Atoi(id)
	// ok: vulnscan.go.sql-injection
	db.Query(fmt.Sprintf("SELECT * FROM users LIMIT %d", n))

	// ruleid: vulnscan.go.command-injection
	exec.Command("sh", "-c", "ping -c 1 "+q)
	// ruleid: vulnscan.go.command-injection
	exec.Command(q)
	// ok: vulnscan.go.command-injection
	exec.Command("ping", "-c", "1", q)

	// ruleid: vulnscan.go.path-traversal
	os.ReadFile(filepath.Join("/srv/files", name))
	// ok: vulnscan.go.path-traversal
	os.ReadFile(filepath.Join("/srv/files", filepath.Base(name)))
	// ruleid: vulnscan.go.path-traversal
	http.ServeFile(w, r, "uploads/"+name)

	// ruleid: vulnscan.go.ssrf
	http.Get(q)
	// ruleid: vulnscan.go.ssrf
	http.Get("http://" + q + "/status")
	// ok: vulnscan.go.ssrf
	http.Get("https://api.example.com/users/" + id)
	// ok: vulnscan.go.ssrf
	http.Get(fmt.Sprintf("https://api.example.com/users/%s", id))

	// ruleid: vulnscan.go.open-redirect
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	// ok: vulnscan.go.open-redirect
	http.Redirect(w, r, "/profile?tab="+q, http.StatusFound)

	// ruleid: vulnscan.go.xss
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
	// ok: vulnscan.go.xss
	fmt.Fprintf(w, "<h1>Hello %s</h1>", html.EscapeString(name))
	// ruleid: vulnscan.go.xss
	io.WriteString(w, q)
	// ruleid: vulnscan.go.xss
	_ = template.HTML(name)

	// ruleid: vulnscan.go.template-injection
	template.New("page").Parse(q)
	// ok: vulnscan.go.template-injection
	template.New("page").Parse("<p>{{.}}</p>")
}

func ginHandler(db *sql.DB, c *gin.Context) {
	var f Filter
	c.ShouldBindJSON(&f)
	// ruleid: vulnscan.go.sql-injection
	db.Exec("DELETE FROM notes WHERE owner = '" + f.Name + "'")
	sort := c.Query("sort")
	// ruleid: vulnscan.go.sql-injection
	db.Order(sort)
	// ok: vulnscan.go.sql-injection
	db.Where(&Filter{Name: sort})
	// ruleid: vulnscan.go.open-redirect
	c.Redirect(302, c.Query("return_to"))
	// ruleid: vulnscan.go.path-traversal
	c.File("/var/data/" + c.Param("file"))
}
