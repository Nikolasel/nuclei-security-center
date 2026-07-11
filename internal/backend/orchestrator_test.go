package backend

import (
	"errors"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/types"
)

func TestScanFindingLines(t *testing.T) {
	line := `{"template-id":"t","host":"h"}`

	// Happy path: three valid lines, one blank, one unparseable.
	in := line + "\n\nnot-json\n" + line + "\n" + line + "\n"
	var got int
	n, skipped, err := scanFindingLines(strings.NewReader(in), 1<<20, 100,
		func(types.NucleiFinding, []byte) error { got++; return nil })
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if n != 3 || got != 3 {
		t.Errorf("ingested = %d (emit called %d), want 3", n, got)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1 (the not-json line)", skipped)
	}
}

func TestScanFindingLinesCountCap(t *testing.T) {
	line := `{"template-id":"t","host":"h"}` + "\n"
	in := strings.Repeat(line, 10)
	n, _, err := scanFindingLines(strings.NewReader(in), 1<<20, 3,
		func(types.NucleiFinding, []byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "finding cap") {
		t.Fatalf("err = %v, want finding-cap error", err)
	}
	if n != 3 {
		t.Errorf("ingested = %d, want exactly the cap (3)", n)
	}
}

func TestScanFindingLinesByteCap(t *testing.T) {
	// A stream longer than the byte cap must abort with a byte-cap error rather
	// than silently truncating.
	in := strings.Repeat(`{"template-id":"t","host":"h"}`+"\n", 100)
	_, _, err := scanFindingLines(strings.NewReader(in), 50, 100_000,
		func(types.NucleiFinding, []byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "byte cap") {
		t.Fatalf("err = %v, want byte-cap error", err)
	}
}

func TestScanFindingLinesEmitError(t *testing.T) {
	line := `{"template-id":"t","host":"h"}` + "\n"
	sentinel := errors.New("db down")
	_, _, err := scanFindingLines(strings.NewReader(line), 1<<20, 100,
		func(types.NucleiFinding, []byte) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the emit error propagated", err)
	}
}
