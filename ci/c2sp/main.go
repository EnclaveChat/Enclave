// Command c2sp-interop checks Enclave witness notes with the reference Go
// implementation of C2SP signed notes and cosignatures
// (golang.org/x/mod/sumdb/note, github.com/transparency-dev/formats/note).
//
//	go run ./ci/c2sp DIR
//
// DIR holds vkeys.txt (one verifier key per line, as a witness serves them)
// and note.txt (a checkpoint cosigned by that witness). Every key must
// verify the note, and the note must parse as a C2SP checkpoint.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/transparency-dev/formats/log"
	tnote "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: c2sp-interop DIR")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "c2sp-interop:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	vk, err := os.ReadFile(filepath.Join(dir, "vkeys.txt"))
	if err != nil {
		return err
	}
	msg, err := os.ReadFile(filepath.Join(dir, "note.txt"))
	if err != nil {
		return err
	}
	keys := strings.Fields(string(vk))
	if len(keys) != 2 {
		return fmt.Errorf("want 2 verifier keys, got %d", len(keys))
	}
	for _, k := range keys {
		v, err := tnote.NewVerifierForCosignatureV1(k)
		if err != nil {
			return fmt.Errorf("verifier key %.40s…: %w", k, err)
		}
		n, err := note.Open(msg, note.VerifierList(v))
		if err != nil {
			return fmt.Errorf("note under %.40s…: %w", k, err)
		}
		if len(n.Sigs) != 1 {
			return fmt.Errorf("want 1 verified signature, got %d", len(n.Sigs))
		}
		t, err := tnote.CoSigV1Timestamp(n.Sigs[0])
		if err != nil {
			return err
		}
		var c log.Checkpoint
		if _, err := c.Unmarshal([]byte(n.Text)); err != nil {
			return fmt.Errorf("checkpoint: %w", err)
		}
		if !strings.HasPrefix(c.Origin, "enclave-kt/") {
			return fmt.Errorf("origin %q", c.Origin)
		}
		fmt.Printf("ok: %s epoch %d cosigned at %s by %s\n", c.Origin, c.Size, t.UTC().Format("2006-01-02T15:04:05Z"), n.Sigs[0].Name)
	}
	return nil
}
