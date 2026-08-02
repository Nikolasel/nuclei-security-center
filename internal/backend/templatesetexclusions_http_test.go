package backend

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

func TestHandleReplaceTemplateSetExclusionsRejectsBadJSON(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/template-sets/abc/exclusions", strings.NewReader("{not json"))
	req.SetPathValue("id", "abc")
	s.handleReplaceTemplateSetExclusions(rr, req)
	if rr.Code != 400 {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestWriteExclusionErrMapsSentinels(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	s.writeExclusionErr(rr, store.ErrInvalidRef)
	if rr.Code != 400 {
		t.Errorf("ErrInvalidRef -> %d, want 400", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.writeExclusionErr(rr, store.ErrTemplateSetExclusionsUnsupported)
	if rr.Code != 409 {
		t.Errorf("ErrTemplateSetExclusionsUnsupported -> %d, want 409", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.writeExclusionErr(rr, store.ErrNotFound)
	if rr.Code != 404 {
		t.Errorf("ErrNotFound -> %d, want 404", rr.Code)
	}
}
