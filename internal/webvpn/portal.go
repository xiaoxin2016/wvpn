package webvpn

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"
)

//go:embed assets/portal.html assets/shim.js
var assetsFS embed.FS

var portalTmpl = template.Must(template.ParseFS(assetsFS, "assets/portal.html"))

var shimJS, _ = assetsFS.ReadFile("assets/shim.js")

// Bookmark is one entry on the landing page.
type Bookmark struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Note string `json:"note,omitempty"`
}

// Category groups bookmarks on the landing page.
type Category struct {
	Name  string     `json:"name"`
	Items []Bookmark `json:"items"`
}

// Portal is the configurable content of the landing page.
type Portal struct {
	// Name is shown in the header and the document title.
	Name string
	// Categories are optional curated links.
	Categories []Category
}

// LoadCategories reads a bookmark file: a JSON array of categories.
func LoadCategories(path string) ([]Category, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cats []Category
	if err := json.Unmarshal(data, &cats); err != nil {
		return nil, fmt.Errorf("webvpn: parsing %s: %w", path, err)
	}
	for _, c := range cats {
		for _, it := range c.Items {
			if _, err := ParseUserInput(it.URL); err != nil {
				return nil, fmt.Errorf("webvpn: %s: bookmark %q has an unusable URL %q", path, it.Name, it.URL)
			}
		}
	}
	return cats, nil
}

type portalItem struct {
	Name string
	// URL is the display form (host plus path); Target is the absolute URL kept
	// for the browser-side "recently visited" list.
	URL    string
	Target string
	Href   string
	Note   string
	Icon   string
}

type portalCategory struct {
	Name  string
	Items []portalItem
}

type portalData struct {
	Name       string
	Email      string
	Admin      bool
	SignedIn   bool
	URLMode    string
	Categories []portalCategory
}

func (h *Handler) servePortal(w http.ResponseWriter, r *http.Request) {
	data := portalData{Name: h.opts.Portal.Name, URLMode: h.codec.Name()}
	if data.Name == "" {
		data.Name = "访问网关"
	}
	if h.opts.Identity != nil {
		data.Email, data.Admin, data.SignedIn = h.opts.Identity.User(r)
	}
	for _, c := range h.opts.Portal.Categories {
		pc := portalCategory{Name: c.Name}
		for _, it := range c.Items {
			u, err := ParseUserInput(it.URL)
			if err != nil {
				continue
			}
			pc.Items = append(pc.Items, portalItem{
				Name:   it.Name,
				URL:    u.Host + u.Path,
				Target: u.String(),
				Href:   h.codec.Encode(u),
				Note:   it.Note,
				Icon:   firstRune(it.Name),
			})
		}
		if len(pc.Items) > 0 {
			data.Categories = append(data.Categories, pc)
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := portalTmpl.Execute(w, data); err != nil {
		h.log.Printf("webvpn: rendering portal: %v", err)
	}
}

func firstRune(s string) string {
	for _, r := range s {
		return string(r)
	}
	return "·"
}

var shimModTime = time.Now()

func serveShim(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	http.ServeContent(w, r, "shim.js", shimModTime, bytes.NewReader(shimJS))
}

// SetCategories replaces the portal's curated links.
func (h *Handler) SetCategories(cats []Category) { h.opts.Portal.Categories = cats }

// SetIdentity attaches the identity layer. sessionCookie names the gateway's
// own cookie, which is then stripped from every upstream request.
func (h *Handler) SetIdentity(id Identity, sessionCookie string) {
	h.opts.Identity = id
	h.opts.SessionCookie = sessionCookie
}
