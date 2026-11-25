package agent

import (
	"strings"
	"testing"

	"github.com/bcyw/artex/db"
)

func TestOOBObservationFactFailureIsAtomicAndVisible(t *testing.T) {
	d, store := recordFactTestStore(t)
	owner := recordFactTestIntent(t, store, "observe callback")
	worker := NewToolSet(store, "oob-worker")
	worker.SetOwnerNode(owner)
	if _, err := d.Exec(`CREATE TRIGGER reject_oob_yields BEFORE INSERT ON exploration_edges
WHEN NEW.rel='yields'
BEGIN SELECT RAISE(ABORT, 'fixture OOB yields failed'); END`); err != nil {
		t.Fatal(err)
	}
	session := &fakeSession{url: "callback.invalid", interactions: []OOBInteraction{
		{Protocol: "dns", UniqueID: "probe-1", Raw: "fixture callback"},
	}}
	tools := oobToolsForRun(worker, session)
	callOOB(t, tools, "oob_generate", t.Context(), `{}`)
	out := callOOB(t, tools, "oob_poll", t.Context(), `{"wait":1}`)
	if out["status"] != "ok" || len(out["interactions"].([]any)) != 1 {
		t.Fatalf("observation lost on persistence failure: %+v", out)
	}
	if saveError, _ := out["fact_error"].(string); !strings.Contains(saveError, "fixture OOB yields failed") {
		t.Errorf("missing persistence error: %+v", out)
	}
	if out["fact_id"] != nil || worker.Writes().Facts != 0 {
		t.Errorf("failed fact was reported as persisted: %+v", out)
	}
	facts, err := store.ListByKind(db.KindFact, 10)
	if err != nil || len(facts) != 0 {
		t.Fatalf("orphan OOB facts persisted: %+v, %v", facts, err)
	}
}
