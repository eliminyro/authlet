package storage

import "testing"

func TestStorageInterfaceShape(t *testing.T) {
	var s Storage
	if s != nil {
		t.Fatal("expected nil interface")
	}
}
