package backend

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Nikolasel/nuclei-security-center/internal/store"
)

// A malformed JSON body is rejected as 400 before the store is touched (nil store
// would panic if reached).
func TestHandleReplaceTemplateSetMembersRejectsBadJSON(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/template-sets/abc/members", strings.NewReader("{not json"))
	req.SetPathValue("id", "abc")
	s.handleReplaceTemplateSetMembers(rr, req)
	if rr.Code != 400 {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

// A bad template id (ErrInvalidRef) maps to 400, distinct from a 404 on the set.
func TestWriteMemberErrMapsInvalidRef(t *testing.T) {
	s := &Server{}
	rr := httptest.NewRecorder()
	s.writeMemberErr(rr, store.ErrInvalidRef)
	if rr.Code != 400 {
		t.Errorf("ErrInvalidRef → %d, want 400", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.writeMemberErr(rr, store.ErrNotFound)
	if rr.Code != 404 {
		t.Errorf("ErrNotFound → %d, want 404", rr.Code)
	}
	rr = httptest.NewRecorder()
	s.writeMemberErr(rr, store.ErrTemplateSetLegacy)
	if rr.Code != 409 {
		t.Errorf("ErrTemplateSetLegacy → %d, want 409", rr.Code)
	}
}

func TestLegacyConversionErrorsAreConflicts(t *testing.T) {
	for _, err := range []error{store.ErrTemplateSetNotLegacy, store.ErrNoTemplateMatches} {
		s := &Server{}
		rr := httptest.NewRecorder()
		s.writeConvertTemplateSetErr(rr, err)
		if rr.Code != 409 {
			t.Errorf("%v → %d, want 409", err, rr.Code)
		}
	}
}
