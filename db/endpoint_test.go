package db

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEndpointCandidateRepeatedObservationsConverge(t *testing.T) {
	d := endpointFixture(t)
	task, err := d.CreateTask("candidates", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := d.Assets()
	for _, method := range []string{"", "GET"} {
		_, _, err := s.RecordEndpointObservation(EndpointObservation{TaskID: task.ID, URL: "https://repeat.example/users/1", Method: method, Source: "static", Evidence: []map[string]any{{"artifact_path": method + ".js", "Cookie": "SECRET"}}})
		if err != nil {
			t.Fatal(err)
		}
	}
	confirmed, asset, err := s.RecordEndpointObservation(EndpointObservation{TaskID: task.ID, URL: "https://repeat.example/users/2", Method: "GET", Source: "traffic"})
	if err != nil {
		t.Fatal(err)
	}
	// An unknown-method static observation arriving late adds provenance rather
	// than competing with the sole confirmed method for the same route.
	id, sameAsset, err := s.RecordEndpointObservation(EndpointObservation{TaskID: task.ID, URL: "https://repeat.example/users/3", Source: "static"})
	if err != nil || id != confirmed || sameAsset != asset {
		t.Errorf("late observation: %d/%d %v", id, sameAsset, err)
	}
	rows, err := s.ListEndpointCandidates(task.ID, "")
	if err != nil || len(rows) != 1 {
		t.Fatalf("competing candidates: %+v %v", rows, err)
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), "SECRET") || !strings.Contains(string(raw), "GET.js") || len(rows[0].Observations) != 4 {
		t.Fatalf("lost or unsafe provenance: %s", raw)
	}
	if _, err := s.DeleteByIDs([]int64{asset}); err != nil {
		t.Fatal(err)
	}
	pending, err := s.ListEndpointCandidates(task.ID, "pending")
	if err != nil || len(pending) != 1 || pending[0].Reason == "" {
		t.Fatalf("deleted asset leaves false confirmation: %v %v", pending, err)
	}
}

func TestEndpointObservationRetryDoesNotInventAnotherObservation(t *testing.T) {
	d := endpointFixture(t)
	task, err := d.CreateTask("observation retry", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := d.Assets()
	obs := EndpointObservation{TaskID: task.ID, URL: "https://retry.example/users/1", Source: "traffic", Method: "GET"}
	candidate, asset, err := s.RecordEndpointObservation(obs)
	if err != nil || asset == 0 {
		t.Fatalf("initial observation failed: %d %d %v", candidate, asset, err)
	}
	before, err := s.ListEndpointCandidates(task.ID, "")
	if err != nil || len(before) != 1 || len(before[0].Observations) != 1 {
		t.Fatalf("initial observation missing: %+v %v", before, err)
	}
	for _, observed := range []time.Time{{}, before[0].Observations[0].ObservedAt} {
		obs.ObservedAt = observed
		sameCandidate, sameAsset, err := s.RecordEndpointObservation(obs)
		if err != nil || sameCandidate != candidate || sameAsset != asset {
			t.Fatalf("retry identity changed: %d %d %v", sameCandidate, sameAsset, err)
		}
	}
	after, err := s.ListEndpointCandidates(task.ID, "")
	if err != nil || len(after) != 1 || len(after[0].Observations) != 1 {
		t.Fatalf("retry invented additional observations: %+v %v", after, err)
	}
	if after[0].Observations[0].ObservedAt.IsZero() || !after[0].Observations[0].ObservedAt.Equal(before[0].Observations[0].ObservedAt) {
		t.Fatalf("retry changed the original observation time: %+v", after[0].Observations)
	}
}

func endpointFixture(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "endpoints.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestEndpointParamsPreserveEvidenceWithoutCredentials(t *testing.T) {
	d := endpointFixture(t)
	s := d.Assets()
	id, err := s.UpsertEndpoint(UpsertEndpointReq{URL: "https://params.example/users", Method: "GET", Params: []map[string]any{
		{"location": "query", "name": "id", "type": "string", "source": "static", "confidence": 0.4, "evidence": []any{map[string]any{"artifact_path": "routes.js:10"}}},
		{"location": "header", "name": "Authorization", "value": "Bearer SECRET", "sample": "SECRET", "samples": []any{"SECRET"}},
		{"location": "header", "name": "Cookie", "value": "session=SECRET"},
		{"location": "body", "name": "access_token", "value": "SECRET"},
		{"location": "body", "name": "profile", "value": map[string]any{"password": "SECRET"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.UpsertEndpoint(UpsertEndpointReq{URL: "https://params.example/users", Method: "GET", Params: []map[string]any{
		{"location": "query", "name": "id", "type": "integer", "source": "traffic", "confidence": 1.0, "evidence": []any{map[string]any{"traffic_id": "flow-1"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	assets, err := s.GetByIDs([]int64{id})
	if err != nil || len(assets) != 1 {
		t.Fatalf("read endpoint: %v, %v", assets, err)
	}
	raw, _ := json.Marshal(assets[0].Params)
	if strings.Contains(string(raw), "SECRET") {
		t.Errorf("credential or nested sample retained in params: %s", raw)
	}
	for _, want := range []string{"routes.js:10", "flow-1", "static", "traffic", "0.4"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("lost parameter provenance %q: %s", want, raw)
		}
	}
	count := 0
	for _, p := range assets[0].Params {
		if p["location"] == "query" && p["name"] == "id" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("parameter identity must merge by location/name: %v", assets[0].Params)
	}
}

func TestEndpointCanonicalIdentity(t *testing.T) {
	d := endpointFixture(t)
	s := d.Assets()
	first, err := s.UpsertEndpoint(UpsertEndpointReq{URL: "https://API.example.com:443/users/1?id=1#details", Method: "get"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.UpsertEndpoint(UpsertEndpointReq{URL: "https://api.example.com/users/2?id=2", Method: "GET",
		Params: []map[string]any{{"location": "body", "name": "id", "type": "integer"}}})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("same service, method and path template must merge: %d != %d", first, second)
	}
	assets, err := s.GetByIDs([]int64{first})
	if err != nil || len(assets) != 1 {
		t.Fatalf("read endpoint: %v, %v", assets, err)
	}
	a := assets[0]
	if a.URL != "https://api.example.com/users/{id}" || a.Method != "GET" {
		t.Fatalf("canonical identity: %s %s", a.Method, a.URL)
	}
	for _, location := range []string{"path", "query", "body"} {
		found := false
		for _, p := range a.Params {
			found = found || p["location"] == location && p["name"] == "id"
		}
		if !found {
			t.Errorf("missing %s/id parameter: %v", location, a.Params)
		}
	}
	post, err := s.UpsertEndpoint(UpsertEndpointReq{URL: "https://api.example.com/users/3", Method: "POST"})
	if err != nil || post == first {
		t.Fatalf("methods must stay distinct: %d, %v", post, err)
	}
}

func TestEndpointDistinctDynamicPathInputs(t *testing.T) {
	s := endpointFixture(t).Assets()
	id, err := s.UpsertEndpoint(UpsertEndpointReq{URL: "https://example.test/users/1/orders/2", Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	assets, err := s.GetByIDs([]int64{id})
	if err != nil || len(assets) != 1 {
		t.Fatalf("read endpoint: %v %v", assets, err)
	}
	if assets[0].URL != "https://example.test/users/{id}/orders/{id2}" {
		t.Fatalf("distinct path inputs lost: %s", assets[0].URL)
	}
	for _, name := range []string{"id", "id2"} {
		found := false
		for _, p := range assets[0].Params {
			found = found || p["location"] == "path" && p["name"] == name
		}
		if !found {
			t.Fatalf("missing path/%s: %v", name, assets[0].Params)
		}
	}
	same, err := s.UpsertEndpoint(UpsertEndpointReq{URL: assets[0].URL, Method: "GET"})
	if err != nil || same != id {
		t.Fatalf("template is not stable: %d %v", same, err)
	}
}

func TestEndpointBelongsToHTTPService(t *testing.T) {
	d := endpointFixture(t)
	s := d.Assets()
	service, err := s.UpsertHTTPService(UpsertHTTPServiceReq{URL: "https://service.example"})
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.UpsertEndpoint(UpsertEndpointReq{URL: "https://service.example:443/users/1", Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	assets, err := s.GetByIDs([]int64{id})
	if err != nil || len(assets) != 1 {
		t.Fatalf("read endpoint: %v, %v", assets, err)
	}
	if assets[0].ServiceID == nil || *assets[0].ServiceID != service {
		t.Errorf("endpoint belongs to service %d, got %v", service, assets[0].ServiceID)
	}
}

func TestEndpointReusesDefaultPortHTTPService(t *testing.T) {
	d := endpointFixture(t)
	s := d.Assets()
	service, err := s.UpsertHTTPService(UpsertHTTPServiceReq{URL: "https://ports.example:443", PageTitle: "known service"})
	if err != nil {
		t.Fatal(err)
	}
	if same, err := s.UpsertHTTPService(UpsertHTTPServiceReq{URL: "https://ports.example"}); err != nil || same != service {
		t.Fatalf("default-port service identity split: %d/%d %v", same, service, err)
	}
	endpoint, err := s.UpsertEndpoint(UpsertEndpointReq{URL: "https://ports.example/users/1", Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	assets, err := s.GetByIDs([]int64{endpoint})
	if err != nil || len(assets) != 1 || assets[0].ServiceID == nil || *assets[0].ServiceID != service {
		t.Fatalf("endpoint did not reuse default-port service %d: %+v %v", service, assets, err)
	}
}

func TestEndpointObservationRespectsTaskScope(t *testing.T) {
	d := endpointFixture(t)
	task, err := d.CreateTask("scoped candidate", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Assets().AddAgentScope(task.ID, "subdomain", "allowed.example", "fixture", "manual"); err != nil {
		t.Fatal(err)
	}
	candidate, asset, err := d.Assets().RecordEndpointObservation(EndpointObservation{
		TaskID: task.ID, URL: "https://outside.example/users/1", Source: "traffic", Method: "GET",
	})
	if err != nil || candidate == 0 || asset != 0 {
		t.Fatalf("out-of-scope observation must remain a candidate: %d %d %v", candidate, asset, err)
	}
	rows, err := d.Assets().ListEndpointCandidates(task.ID, "pending")
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].Reason, "outside task scope") {
		t.Fatalf("missing out-of-scope reason: %+v %v", rows, err)
	}
}

func TestEndpointObservationAcceptsServiceIPInsideCIDRScope(t *testing.T) {
	d := endpointFixture(t)
	task, err := d.CreateTask("cidr scoped service", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO task_scope(task_id,kind,net,source,reason) VALUES($1,'cidr','10.20.0.0/16','manual','fixture')`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, asset, err := d.Assets().RecordEndpointObservation(EndpointObservation{
		TaskID: task.ID, URL: "https://unmapped.example/api/users/1", Method: "GET", Source: "traffic",
	}); err != nil || asset != 0 {
		t.Fatalf("unmapped hostname must not bypass CIDR scope: asset=%d err=%v", asset, err)
	}
	if _, err := d.Assets().UpsertHTTPService(UpsertHTTPServiceReq{
		URL: "https://network.example", IP: "10.20.1.2", TaskID: task.ID,
	}); err != nil {
		t.Fatal(err)
	}
	_, asset, err := d.Assets().RecordEndpointObservation(EndpointObservation{
		TaskID: task.ID, URL: "https://network.example/api/users/1", Method: "GET", Source: "traffic",
	})
	if err != nil || asset == 0 {
		t.Fatalf("service with in-scope IP should allow endpoint confirmation: asset=%d err=%v", asset, err)
	}
}

func TestEndpointUnknownMethodSurvivesMultipleConfirmedMethods(t *testing.T) {
	d := endpointFixture(t)
	task, err := d.CreateTask("method conflict", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := d.Assets()
	for _, method := range []string{"GET", "POST"} {
		if _, asset, err := s.RecordEndpointObservation(EndpointObservation{
			TaskID: task.ID, URL: "https://methods.example/users/1", Source: "traffic", Method: method,
		}); err != nil || asset == 0 {
			t.Fatalf("confirm %s: asset=%d err=%v", method, asset, err)
		}
	}
	unknown, asset, err := s.RecordEndpointObservation(EndpointObservation{
		TaskID: task.ID, URL: "https://methods.example/users/2", Source: "static",
		Params: []map[string]any{{"location": "body", "name": "filter"}},
	})
	if err != nil || unknown == 0 || asset != 0 {
		t.Fatalf("unknown method must remain pending: %d %d %v", unknown, asset, err)
	}
	if _, asset, err := s.RecordEndpointObservation(EndpointObservation{
		TaskID: task.ID, URL: "https://methods.example/users/3", Source: "traffic", Method: "GET",
	}); err != nil || asset == 0 {
		t.Fatalf("repeat GET confirmation: %d %v", asset, err)
	}
	pending, err := s.ListEndpointCandidates(task.ID, "pending")
	if err != nil || len(pending) != 1 || pending[0].ID != unknown || pending[0].Method != "" {
		t.Fatalf("ambiguous unknown candidate was absorbed: %+v %v", pending, err)
	}
}

func TestExplicitStaticCallEvidenceConfirmsEndpoint(t *testing.T) {
	d := endpointFixture(t)
	task, err := d.CreateTask("static confirmation", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	candidate, asset, err := d.Assets().RecordEndpointObservation(EndpointObservation{
		TaskID: task.ID, URL: "https://static.example/api/users/1", Method: "GET", Source: "static",
		Evidence: []map[string]any{{"code_location": "client.go:42"}},
	})
	if err != nil || candidate == 0 || asset == 0 {
		t.Fatalf("explicit static call evidence should confirm endpoint: %d %d %v", candidate, asset, err)
	}
	confirmed, err := d.Assets().ListEndpointCandidates(task.ID, "confirmed")
	if err != nil || len(confirmed) != 1 || confirmed[0].ID != candidate || confirmed[0].Observations[0].Source != "static" {
		t.Fatalf("static confirmation provenance not preserved: %+v %v", confirmed, err)
	}
}

func TestUnresolvedEndpointObservationRedactsSensitiveURL(t *testing.T) {
	d := endpointFixture(t)
	task, err := d.CreateTask("unresolved url", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, observedURL := range []string{
		"/api/users?token=SECRET&keep=ok",
		"https://user:SECRET@example.test/%zz?token=SECRET",
		"//user:SECRET@example.test/%zz?token=SECRET",
	} {
		_, asset, err := d.Assets().RecordEndpointObservation(EndpointObservation{
			TaskID: task.ID, URL: observedURL, Source: "static",
		})
		if err != nil || asset != 0 {
			t.Fatalf("unresolved URL should remain candidate: %q %d %v", observedURL, asset, err)
		}
	}
	rows, err := d.Assets().ListEndpointCandidates(task.ID, "pending")
	if err != nil || len(rows) != 3 {
		t.Fatalf("read unresolved candidates: %+v %v", rows, err)
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), "SECRET") || !strings.Contains(strings.ToLower(string(raw)), "redacted") {
		t.Fatalf("unresolved URL leaked query credential: %s", raw)
	}
}

func TestEndpointObservationRedactsPasswordQueryAliases(t *testing.T) {
	d := endpointFixture(t)
	task, err := d.CreateTask("password query redaction", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"passwd", "pwd", "auth"} {
		if _, asset, err := d.Assets().RecordEndpointObservation(EndpointObservation{
			TaskID: task.ID, URL: "https://credentials.example/api?" + name + "=SECRET", Source: "static",
		}); err != nil || asset != 0 {
			t.Fatalf("credential-only static observation should remain a candidate: asset=%d err=%v", asset, err)
		}
	}
	candidates, err := d.Assets().ListEndpointCandidates(task.ID, "pending")
	if err != nil || len(candidates) != 1 {
		t.Fatalf("expected one merged candidate: %+v %v", candidates, err)
	}
	encoded, _ := json.Marshal(candidates)
	if strings.Contains(string(encoded), "SECRET") || !strings.Contains(strings.ToLower(string(encoded)), "redacted") {
		t.Fatalf("password query alias leaked: %s", encoded)
	}
}

func TestUnconfirmedStaticMethodDoesNotPolluteConfirmedAsset(t *testing.T) {
	d := endpointFixture(t)
	task, err := d.CreateTask("static method guess", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := d.Assets()
	confirmedCandidate, asset, err := s.RecordEndpointObservation(EndpointObservation{
		TaskID: task.ID, URL: "https://guess.example/users/1", Method: "GET", Source: "traffic",
	})
	if err != nil || asset == 0 {
		t.Fatalf("traffic observation did not confirm: %d %v", asset, err)
	}
	candidate, guessedAsset, err := s.RecordEndpointObservation(EndpointObservation{
		TaskID: task.ID, URL: "https://guess.example/users/2", Method: "GET", MethodCandidate: true,
		Source: "static", Params: []map[string]any{{"location": "query", "name": "debug"}},
	})
	if err != nil || candidate != confirmedCandidate || guessedAsset != 0 {
		t.Fatalf("unconfirmed static method should be retained without promotion: candidate=%d asset=%d err=%v", candidate, guessedAsset, err)
	}
	assets, err := s.GetByIDs([]int64{asset})
	if err != nil || len(assets) != 1 {
		t.Fatalf("read confirmed asset: %v %v", assets, err)
	}
	raw, _ := json.Marshal(assets[0].Params)
	if strings.Contains(string(raw), "debug") {
		t.Fatalf("unconfirmed static parameter polluted asset: %s", raw)
	}
	pending, err := s.ListEndpointCandidates(task.ID, "pending")
	if err != nil || len(pending) != 0 {
		t.Fatalf("confirmed method must not create a conflicting pending candidate: %+v %v", pending, err)
	}
	confirmed, err := s.ListEndpointCandidates(task.ID, "confirmed")
	if err != nil || len(confirmed) != 1 || confirmed[0].ID != confirmedCandidate || confirmed[0].AssetID != asset {
		t.Fatalf("confirmed route was not preserved: %+v %v", confirmed, err)
	}
	if strings.Contains(string(mustJSON(confirmed[0].Params)), "debug") || !strings.Contains(string(mustJSON(confirmed[0].Observations)), "debug") {
		t.Fatalf("static guess must remain observation-only: %+v", confirmed[0])
	}
}

func mustJSON(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestEndpointCandidateConfirmedByTraffic(t *testing.T) {
	d := endpointFixture(t)
	task, err := d.CreateTask("candidate", "candidate", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := d.Assets()
	observed := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	candidate, asset, err := s.RecordEndpointObservation(EndpointObservation{
		TaskID: task.ID, URL: "https://candidate.example/users/1", Source: "static", ObservedAt: observed,
		Params:   []map[string]any{{"location": "body", "name": "filter", "confidence": 0.4}},
		Evidence: []map[string]any{{"artifact_path": "routes.js:10"}},
	})
	if err != nil || candidate == 0 || asset != 0 {
		t.Fatalf("static observation must only create a candidate: %d %d %v", candidate, asset, err)
	}
	pending, err := s.ListEndpointCandidates(task.ID, "pending")
	if err != nil || len(pending) != 1 || pending[0].Method != "" || pending[0].Reason == "" {
		t.Fatalf("missing method must survive without inventing GET: %+v %v", pending, err)
	}
	if endpoints, err := s.QueryByTask(task.ID, "endpoint", 10, 0); err != nil || len(endpoints) != 0 {
		t.Fatalf("candidate leaked into assets: %v %v", endpoints, err)
	}
	_, asset, err = s.RecordEndpointObservation(EndpointObservation{
		TaskID: task.ID, URL: "https://candidate.example/users/2", Method: "GET", Source: "traffic",
		Evidence: []map[string]any{{"traffic_id": "flow-1"}},
	})
	if err != nil || asset == 0 {
		t.Fatalf("traffic must confirm endpoint: %d %v", asset, err)
	}
	pending, err = s.ListEndpointCandidates(task.ID, "pending")
	if err != nil || len(pending) != 0 {
		t.Fatalf("confirmed candidate must stop competing: %+v %v", pending, err)
	}
	confirmed, err := s.ListEndpointCandidates(task.ID, "confirmed")
	if err != nil || len(confirmed) != 1 || confirmed[0].ID != candidate || confirmed[0].AssetID != asset {
		t.Fatalf("candidate must retain its identity and link to asset: %+v %v", confirmed, err)
	}
	raw, _ := json.Marshal(confirmed)
	for _, want := range []string{"routes.js:10", "flow-1", "static", "traffic", "2026-11-25T10:00:00Z", "/users/1", "/users/{id}"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("lost observation %q: %s", want, raw)
		}
	}
	assets, err := s.GetByIDs([]int64{asset})
	if err != nil || len(assets) != 1 {
		t.Fatalf("read confirmed asset: %v %v", assets, err)
	}
	raw, _ = json.Marshal(assets[0].Params)
	if !strings.Contains(string(raw), "filter") || !strings.Contains(string(raw), "routes.js:10") {
		t.Fatalf("confirmation lost candidate parameters/provenance: %s", raw)
	}
}

func TestEndpointCandidatesRetainUncertaintyAndTaskIsolation(t *testing.T) {
	d := endpointFixture(t)
	task, err := d.CreateTask("candidate", "candidate", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := d.CreateTask("other", "other", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := d.Assets()
	for _, obs := range []EndpointObservation{
		{URL: "https://candidate.example/users/1", Source: "static", Method: "POST", MethodCandidate: true},
		{URL: "https://outside.example/users/1", ServiceURL: "https://candidate.example", Source: "traffic", Method: "GET"},
		{URL: "https://candidate.example/${resource}", Source: "static"},
		{URL: "not an absolute URL", Source: "static", ParseStatus: "unresolved", Reason: "missing base URL"},
		{URL: "https://candidate.example/abcdefghijklmnopqrstuvwxyz", Source: "static"},
	} {
		obs.TaskID = task.ID
		if id, asset, err := s.RecordEndpointObservation(obs); err != nil || id == 0 || asset != 0 {
			t.Fatalf("uncertain observation must be retained as candidate: %s: %d %d %v", obs.URL, id, asset, err)
		}
	}
	if _, asset, err := s.RecordEndpointObservation(EndpointObservation{TaskID: task.ID, URL: "https://candidate.example/users/2", Source: "traffic", Method: "GET"}); err != nil || asset == 0 {
		t.Fatalf("confirm GET independently: %d %v", asset, err)
	}
	pending, err := s.ListEndpointCandidates(task.ID, "pending")
	if err != nil || len(pending) != 5 {
		t.Fatalf("method conflict/uncertain candidates must survive: %+v %v", pending, err)
	}
	for _, c := range pending {
		if c.Reason == "" {
			t.Errorf("candidate %d lacks an uncertainty reason", c.ID)
		}
		if c.PathTemplate == "/{token}" {
			t.Errorf("a long literal resource name must not be guessed to be a token")
		}
	}
	if candidates, err := s.ListEndpointCandidates(other.ID, ""); err != nil || len(candidates) != 0 {
		t.Fatalf("candidate leaked across tasks: %v %v", candidates, err)
	}
}
