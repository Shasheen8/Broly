package routes

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func find(inv *Inventory, method, path string) *Route {
	for i := range inv.Routes {
		if inv.Routes[i].Method == method && inv.Routes[i].PathTemplate == path {
			return &inv.Routes[i]
		}
	}
	return nil
}

func TestExtract_GoRouterAndServeMux(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"main.go": `package main

func routes(r chi.Router, mux *http.ServeMux) {
	r.Get("/users/{id}", getUser)
	r.Post("/users", createUser)
	mux.HandleFunc("DELETE /admin/purge", purge)
}
`})

	inv, err := Extract(root)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if r := find(inv, "GET", "/users/{id}"); r == nil {
		t.Error("missed chi GET route")
	} else if len(r.Params) != 1 || r.Params[0] != "id" {
		t.Errorf("params = %v, want [id]", r.Params)
	}
	if find(inv, "POST", "/users") == nil {
		t.Error("missed chi POST route")
	}
	if find(inv, "DELETE", "/admin/purge") == nil {
		t.Error("missed go1.22 ServeMux method-prefixed route")
	}
}

// A header read through a Get-shaped call must not become a route. Fiber's
// c.Get("X-API-Key") produced exactly this before paths had to be rooted.
func TestExtract_HeaderReadIsNotARoute(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"h.go": `package main

func h(c *fiber.Ctx) error {
	key := c.Get("X-API-Key")
	other := c.Get("Content-Type")
	_ = key
	_ = other
	return nil
}
`})

	inv, err := Extract(root)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	for _, r := range inv.Routes {
		t.Errorf("header read became a route: %s %s", r.Method, r.PathTemplate)
	}
}

func TestExtract_PythonFrameworks(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"api.py": `
@app.get("/items/{item_id}")
def read_item(item_id: int):
    pass

@app.route("/legacy")
def legacy():
    pass
`})

	inv, err := Extract(root)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if r := find(inv, "GET", "/items/{item_id}"); r == nil {
		t.Error("missed FastAPI route")
	} else if len(r.Params) != 1 {
		t.Errorf("params = %v, want [item_id]", r.Params)
	}
	if find(inv, "ANY", "/legacy") == nil {
		t.Error("missed Flask route (no explicit method)")
	}
}

func TestExtract_ExpressRoutes(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"server.js": `
app.get('/api/health', (req, res) => res.send('ok'));
router.post("/api/users/:id/reset", resetHandler);
`})

	inv, err := Extract(root)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if find(inv, "GET", "/api/health") == nil {
		t.Error("missed express GET route")
	}
	if r := find(inv, "POST", "/api/users/:id/reset"); r == nil {
		t.Error("missed express POST route")
	} else if len(r.Params) != 1 || r.Params[0] != "id" {
		t.Errorf("params = %v, want [id]", r.Params)
	}
}

// Spec-driven frameworks register everything at startup, so the source has
// no route literals at all. Missing this reports a clean zero for a service
// that in fact exposes a full API.
func TestExtract_OpenAPISpecIsAuthoritative(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"config.py": "vuln_app = connexion.App(__name__, specification_dir='./openapi_specs')\n",
		"openapi_specs/openapi3.yml": `openapi: 3.0.1
servers:
  - url: http://localhost:5000/v1
paths:
  /users:
    get:
      operationId: list_users
    post:
      operationId: create_user
      security:
        - bearerAuth: []
  /users/{username}:
    delete:
      operationId: delete_user
      security:
        - bearerAuth: []
`})

	inv, err := Extract(root)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	// The server URL carries the served prefix, which the source does not
	// know. That prefix is the whole reason a spec beats pattern matching.
	if find(inv, "GET", "/v1/users") == nil {
		t.Errorf("expected the server prefix to be applied; got %+v", inv.Routes)
	}
	if r := find(inv, "POST", "/v1/users"); r == nil {
		t.Error("missed POST from spec")
	} else if r.AuthGuard != "bearer" {
		t.Errorf("AuthGuard = %q, want bearer", r.AuthGuard)
	}
	if r := find(inv, "DELETE", "/v1/users/{username}"); r == nil {
		t.Error("missed DELETE from spec")
	} else if len(r.Params) != 1 || r.Params[0] != "username" {
		t.Errorf("params = %v, want [username]", r.Params)
	}
}

func TestExtract_SpecWithExplicitlyEmptySecurityIsUnauthenticated(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"openapi.yaml": `openapi: 3.0.0
paths:
  /public/ping:
    get:
      security: []
`})

	inv, err := Extract(root)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	r := find(inv, "GET", "/public/ping")
	if r == nil {
		t.Fatal("missed the route")
	}
	if r.AuthGuard != "none" {
		t.Errorf("AuthGuard = %q, want none — an empty security array is an explicit opt-out", r.AuthGuard)
	}
}

// A YAML file that happens to live near a spec must not be parsed as one.
func TestExtract_NonSpecYAMLIsIgnored(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"openapi/docker-compose.yaml": "services:\n  web:\n    image: nginx\n",
	})

	inv, err := Extract(root)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if len(inv.Routes) != 0 {
		t.Errorf("parsed a non-spec YAML as a spec: %+v", inv.Routes)
	}
}

func TestExtract_SinksAreAttachedToRoutes(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"handler.go": `package main

func h(w http.ResponseWriter, r *http.Request) {
	db.Query("SELECT * FROM users WHERE id = " + r.URL.Query().Get("id"))
	http.Get(r.URL.Query().Get("next"))
}

func register(mux *http.ServeMux) {
	mux.HandleFunc("/report", h)
}
`})

	inv, err := Extract(root)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	r := find(inv, "ANY", "/report")
	if r == nil {
		t.Fatal("missed the route")
	}
	kinds := map[string]bool{}
	for _, s := range r.Sinks {
		kinds[s.Kind] = true
	}
	for _, want := range []string{"sqli", "ssrf"} {
		if !kinds[want] {
			t.Errorf("expected a %s sink, got %v", want, kinds)
		}
	}
}

func TestExtract_NextJSFileRoutes(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"pages/api/users/[id].ts": "export default function handler(req, res) {}\n",
		"app/api/health/route.ts": "export async function GET() {}\n",
	})

	inv, err := Extract(root)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if r := find(inv, "ANY", "/api/users/{id}"); r == nil {
		t.Errorf("missed pages/api dynamic route; got %+v", inv.Routes)
	} else if len(r.Params) != 1 || r.Params[0] != "id" {
		t.Errorf("params = %v, want [id]", r.Params)
	}
	if find(inv, "ANY", "/api/health") == nil {
		t.Errorf("missed app/api route handler; got %+v", inv.Routes)
	}
}

// The inventory must always say it is a floor, so a consumer never reads an
// absent route as a route that does not exist.
func TestExtract_AlwaysWarnsThatItIsAFloor(t *testing.T) {
	root := writeRepo(t, map[string]string{"main.go": "package main\n"})

	inv, err := Extract(root)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if len(inv.Warnings) == 0 {
		t.Fatal("expected a warning stating the extraction is pattern-based")
	}
}

func TestExtract_TestFilesAreSkipped(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"handler_test.go": `package main

func TestX(t *testing.T) {
	r.Get("/only-in-tests", h)
}
`})

	inv, err := Extract(root)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if find(inv, "GET", "/only-in-tests") != nil {
		t.Error("a route declared inside a test file was reported as real surface")
	}
}
