package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// seedFinding 建一条真实漏洞，批量接口的用例都需要它。
func seedFinding(t *testing.T, s *Server, m *Manager, name string) int64 {
	t.Helper()
	tk, err := m.pg.CreateTask("批量接口-"+t.Name(), "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(tk.ID) })
	es := m.pg.Exploration(tk.ExplorationID)
	nodeID, err := es.AddNode(db.KindFinding, map[string]any{"summary": "x", "severity": "high"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := m.pg.AddFinding(tk.ID, nodeID, "XSS", name, db.SeverityHigh, "summary", "poc", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	return fid
}

func newBatchTestServer(t *testing.T) *Server {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	td := t.TempDir()
	return New(context.Background(), m, td, td, td)
}

// doBatch 发出一次带鉴权的批量请求并返回响应记录。
func doBatch(t *testing.T, s *Server, rec *httptest.ResponseRecorder, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	req := httptest.NewRequest(method, "/api/exploration/findings/batch", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// TestFindingsBatchRoutesRegistered 确认 /batch 没被 {id} 通配吞掉。
//
// net/http 的 ServeMux 按注册顺序匹配，{id} 段能匹配任意非空路径，
// 所以这条断言是「路由真的可用」而不是走个过场。
func TestFindingsBatchRoutesRegistered(t *testing.T) {
	s := newBatchTestServer(t)
	rec := doBatch(t, s, httptest.NewRecorder(), http.MethodDelete, `{"finding_ids":[1]}`)
	if strings.Contains(rec.Body.String(), "404 page not found") {
		t.Fatalf("/batch 被 {id} 通配吞掉了: %s", rec.Body.String())
	}
}

// TestPatchFindingsBatchHTTP 覆盖改状态的正常路径与几条校验分支。
func TestPatchFindingsBatchHTTP(t *testing.T) {
	s := newBatchTestServer(t)
	m := s.m
	first := seedFinding(t, s, m, "甲")
	second := seedFinding(t, s, m, "乙")

	rec := doBatch(t, s, httptest.NewRecorder(), http.MethodPatch,
		`{"finding_ids":[`+strconv.FormatInt(first, 10)+`,`+strconv.FormatInt(second, 10)+`,999999999],"status":"resolved"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp batchFindingResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应: %v body=%s", err, rec.Body.String())
	}
	if resp.Updated != 2 || resp.Skipped != 1 {
		t.Errorf("updated/skipped: want 2/1, got %d/%d", resp.Updated, resp.Skipped)
	}
	for _, id := range []int64{first, second} {
		f, err := m.pg.GetFinding(id)
		if err != nil || f == nil || f.Status != "resolved" {
			t.Errorf("漏洞 %d 未改成 resolved: %+v %v", id, f, err)
		}
	}

	// 非法状态必须 400
	bad := doBatch(t, s, httptest.NewRecorder(), http.MethodPatch,
		`{"finding_ids":[`+strconv.FormatInt(first, 10)+`],"status":"nope"}`)
	if bad.Code != http.StatusBadRequest {
		t.Errorf("非法状态: want 400, got %d body=%s", bad.Code, bad.Body.String())
	}

	// 缺 status 必须 400
	missing := doBatch(t, s, httptest.NewRecorder(), http.MethodPatch,
		`{"finding_ids":[`+strconv.FormatInt(first, 10)+`]}`)
	if missing.Code != http.StatusBadRequest {
		t.Errorf("缺 status: want 400, got %d body=%s", missing.Code, missing.Body.String())
	}

	// 空 id 列表必须 400
	empty := doBatch(t, s, httptest.NewRecorder(), http.MethodPatch,
		`{"finding_ids":[],"status":"resolved"}`)
	if empty.Code != http.StatusBadRequest {
		t.Errorf("空 id 列表: want 400, got %d body=%s", empty.Code, empty.Body.String())
	}
}

// TestDeleteFindingsBatchHTTP 覆盖批量删除，并确认通知事件一并清理。
func TestDeleteFindingsBatchHTTP(t *testing.T) {
	s := newBatchTestServer(t)
	m := s.m
	first := seedFinding(t, s, m, "待删")
	second := seedFinding(t, s, m, "待删二")

	if _, err := m.pg.Exec(`INSERT INTO notification_events(kind,finding_id,snapshot)
		VALUES('finding_created',$1,'{}')`, first); err != nil {
		t.Fatal(err)
	}

	rec := doBatch(t, s, httptest.NewRecorder(), http.MethodDelete,
		`{"finding_ids":[`+strconv.FormatInt(first, 10)+`,`+strconv.FormatInt(second, 10)+`,999999999]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp batchFindingResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应: %v", err)
	}
	if resp.Deleted != 2 || resp.Skipped != 1 {
		t.Errorf("deleted/skipped: want 2/1, got %d/%d", resp.Deleted, resp.Skipped)
	}
	for _, id := range []int64{first, second} {
		if f, _ := m.pg.GetFinding(id); f != nil {
			t.Errorf("漏洞 %d 应已删除", id)
		}
	}
	var events int
	if err := m.pg.QueryRow(`SELECT count(*) FROM notification_events WHERE finding_id=$1`, first).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Errorf("通知事件应一并清理, 残留 %d 行", events)
	}
}

// TestNormalizeFindingBatchIDs 去重与非正数过滤。
func TestNormalizeFindingBatchIDs(t *testing.T) {
	got := normalizeFindingBatchIDs([]int64{3, 0, -1, 3, 5, 5, 7})
	want := []int64{3, 5, 7}
	if len(got) != len(want) {
		t.Fatalf("去重结果: want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("去重结果: want %v, got %v", want, got)
		}
	}
}
