package auth

import (
	"embed"
	"strings"
	"text/template"
)

//go:embed assets/*.html
var assetsFS embed.FS

// renderMailBody expands the configured body template.
func renderMailBody(body, email, code string, minutes int) (string, error) {
	t, err := template.New("mail").Parse(body)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	err = t.Execute(&b, map[string]any{"Email": email, "Code": code, "Minutes": minutes})
	return b.String(), err
}
