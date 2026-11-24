// DEMO FILE - intentionally vulnerable.
// Showcases the review tool. Every issue here is deliberate.
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"text/template"
)

func getUser(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	// SECU: hardcoded credential in a short declaration
	dbPassword := "supers3cret"
	_ = dbPassword

	id := r.URL.Query().Get("id")
	// SQL built by string concatenation
	row := db.QueryRow("SELECT * FROM users WHERE id = " + id)

	var name string
	_ = row.Scan(&name)
	fmt.Fprint(w, name)
}

func runTool(name string) {
	// SECU-220: shell command execution
	cmd := exec.Command("sh", "-c", "ls "+name)
	_ = cmd.Run()
}

func render(w http.ResponseWriter, data string) {
	// SECU-221: unescaped HTML in template
	t := template.Must(template.New("x").Parse("<div>" + data + "</div>"))
	_ = t.Execute(w, nil)
}