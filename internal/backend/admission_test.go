package backend

import (
	"errors"
	"testing"
)

func TestScanAdmissionRejectsWhenFullAndReleases(t *testing.T) {
	admission := newScanAdmission()

	if err := admission.acquire("node-a", 1); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := admission.acquire("node-a", 1); !errors.Is(err, ErrScanCapacity) {
		t.Fatalf("second acquire = %v, want ErrScanCapacity", err)
	}

	if err := admission.acquire("node-b", 1); err != nil {
		t.Fatalf("independent node acquire: %v", err)
	}
	admission.release("node-a")
	if err := admission.acquire("node-a", 1); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	admission.release("node-a")
	admission.release("node-b")
}
