package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Shasheen8/Broly/pkg/routes"
)

func routesCmd() *cobra.Command {
	var (
		format     string
		output     string
		withSinks  bool
		minRoutes  int
		showParams bool
	)

	cmd := &cobra.Command{
		Use:   "routes [path]",
		Short: "Extract the HTTP routes a repository declares",
		Long: `Extract the HTTP routes a repository declares, and the dangerous sinks
reachable from each handler.

This is not a vulnerability scan. It answers "what surface does this code
expose, and where does each entry point lead", which is the input a
black-box scanner needs to stop guessing at endpoints.

Routes are matched by pattern, not by parsing. A route assembled at runtime
or registered through an unrecognised wrapper will be missed, so the output
is a floor on the declared surface rather than a complete enumeration.

FRAMEWORKS
  Go          chi, gin, echo, fiber, gorilla/mux, net/http, go1.22 ServeMux
  Python      FastAPI, Flask, Django
  JavaScript  Express, Koa, Fastify, NestJS, Next.js file routes
  Ruby        Rails
  Java        Spring

EXAMPLES
  broly routes . --format json
  broly routes ./api --format json --output routes.json`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}

			inv, err := routes.Extract(root)
			if err != nil {
				return fmt.Errorf("extracting routes from %s: %w", root, err)
			}
			if !withSinks {
				for i := range inv.Routes {
					inv.Routes[i].Sinks = nil
				}
			}

			var rendered string
			switch strings.ToLower(format) {
			case "json":
				data, err := json.MarshalIndent(inv, "", "  ")
				if err != nil {
					return fmt.Errorf("encoding route inventory: %w", err)
				}
				rendered = string(data) + "\n"
			case "table", "":
				rendered = renderRoutesTable(inv, showParams)
			default:
				return fmt.Errorf("unknown format %q (want json or table)", format)
			}

			if output != "" {
				if err := os.WriteFile(output, []byte(rendered), 0o600); err != nil {
					return fmt.Errorf("writing %s: %w", output, err)
				}
			} else {
				fmt.Print(rendered)
			}

			// A non-zero --min-routes turns a thin extraction into a failure,
			// so CI can catch the case where a framework change silently
			// stops the extractor from recognising anything.
			if minRoutes > 0 && len(inv.Routes) < minRoutes {
				return fmt.Errorf("found %d routes, expected at least %d", len(inv.Routes), minRoutes)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table, json")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Write output to a file instead of stdout")
	cmd.Flags().BoolVar(&withSinks, "sinks", true, "Include reachable sinks per route")
	cmd.Flags().BoolVar(&showParams, "params", true, "Show path parameters in table output")
	cmd.Flags().IntVar(&minRoutes, "min-routes", 0, "Exit non-zero if fewer than N routes are found")
	return cmd
}

func renderRoutesTable(inv *routes.Inventory, showParams bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d routes across %d files\n\n", len(inv.Routes), inv.FilesScanned)

	if len(inv.Routes) > 0 {
		width := 0
		for _, r := range inv.Routes {
			if n := len(r.PathTemplate); n > width {
				width = n
			}
		}
		if width > 60 {
			width = 60
		}
		for _, r := range inv.Routes {
			fmt.Fprintf(&b, "  %-7s %-*s  %s:%d", r.Method, width, r.PathTemplate, r.HandlerFile, r.HandlerLine)
			if r.AuthGuard != "" {
				fmt.Fprintf(&b, "  auth=%s", r.AuthGuard)
			}
			if showParams && len(r.Params) > 0 {
				fmt.Fprintf(&b, "  params=%s", strings.Join(r.Params, ","))
			}
			if kinds := sinkKinds(r.Sinks); len(kinds) > 0 {
				fmt.Fprintf(&b, "  sinks=%s", strings.Join(kinds, ","))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	for _, w := range inv.Warnings {
		fmt.Fprintf(&b, "note: %s\n", w)
	}
	return b.String()
}

func sinkKinds(sinks []routes.Sink) []string {
	if len(sinks) == 0 {
		return nil
	}
	out := make([]string, 0, len(sinks))
	for _, s := range sinks {
		out = append(out, s.Kind)
	}
	sort.Strings(out)
	return out
}
