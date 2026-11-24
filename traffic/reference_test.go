package traffic

import (
	"testing"
)

// Evidence handoffs must be able to cite a captured exchange only when it
// actually exists; the excerpt is what the worker looks at later.
func TestReferenceExcerptDescribesStoredExchange(t *testing.T) {
	tr, _ := openTraffic(t)
	tr.record(newFlow("ref.example.com", "POST", "/login", []byte("u=a"), []byte(`{"ok":true}`)))
	id := onlyExchangeID(t, tr)
	excerpt, ok := tr.ReferenceExcerpt(id)
	if !ok || excerpt == "" {
		t.Fatalf("existing exchange should yield a readable excerpt: %q %v", excerpt, ok)
	}
	if _, ok := tr.ReferenceExcerpt("does-not-exist"); ok {
		t.Fatal("unknown exchange id must not be reported as existing evidence")
	}
}
