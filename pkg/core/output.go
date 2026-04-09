package core

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

var stdlogMu sync.Mutex

func Progressf(quiet bool, format string, args ...any) {
	if quiet {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func Warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", args...)
}

func WithSuppressedStdlog(fn func()) {
	stdlogMu.Lock()
	defer stdlogMu.Unlock()

	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	prevWriter := log.Writer()

	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(io.Discard)
	defer func() {
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
		log.SetOutput(prevWriter)
	}()

	fn()
}
