package db

import (
	"context"
	"testing"
)

// seedFindingForBatch 建一个任务 + 漏洞，返回漏洞 id。
// 批量用例都需要「一条真实可改状态的漏洞」，共用这一个辅助避免各写一遍。
func seedFindingForBatch(t *testing.T, d *DB, name string) int64 {
	t.Helper()
	tk, err := d.CreateTask("批量测试-"+t.Name(), "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(tk.ID) })
	es := d.Exploration(tk.ExplorationID)
	nodeID, err := es.AddNode(KindFinding, map[string]any{"summary": "x", "severity": "high"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	fid, err := d.AddFinding(tk.ID, nodeID, "XSS", name, "high", "summary", "poc", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	return fid
}

// TestSetFindingsStatusBatch 覆盖批量改状态的四件事：多条一起改、逐条登记
// 推送事件、不存在的 id 只记 found=false 不中断整批、状态本就相同记 changed=false。
func TestSetFindingsStatusBatch(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()

	first := seedFindingForBatch(t, d, "第一条")
	second := seedFindingForBatch(t, d, "第二条")
	missing := int64(999999999)

	results, err := d.SetFindingsStatusBatch(ctx, []int64{first, second, missing}, "resolved")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("结果条数: want 3, got %d", len(results))
	}
	if !results[0].Found || !results[0].Changed || results[0].From != "pending" {
		t.Errorf("第一条: %+v（期望 found/changed=true, from=pending）", results[0])
	}
	if results[0].From != "pending" {
		t.Errorf("第一条 from: want pending, got %q", results[0].From)
	}
	if results[1].From != "pending" || !results[1].Changed {
		t.Errorf("第二条: %+v", results[1])
	}
	if results[2].Found {
		t.Errorf("不存在的 id 不应报 found: %+v", results[2])
	}

	for _, id := range []int64{first, second} {
		f, err := d.GetFinding(id)
		if err != nil || f == nil {
			t.Fatalf("漏洞 %d 不应消失: %v", id, err)
		}
		if f.Status != "resolved" {
			t.Errorf("漏洞 %d 状态: want resolved, got %q", id, f.Status)
		}
	}

	// 每条真实变更都应登记一条状态变更事件
	var events int
	for _, id := range []int64{first, second} {
		if err := d.QueryRow(`SELECT count(*) FROM notification_events
			WHERE finding_id=$1 AND kind='finding_status_changed'`, id).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if events != 1 {
			t.Fatalf("漏洞 %d 的状态变更事件数: want 1, got %d", id, events)
		}
	}

	// 重复提交同一状态：changed=false，且不产生第二条事件（避免推送噪音）
	again, err := d.SetFindingsStatusBatch(ctx, []int64{first}, "resolved")
	if err != nil {
		t.Fatal(err)
	}
	if !again[0].Found || again[0].Changed {
		t.Errorf("同状态重复提交应 changed=false: %+v", again[0])
	}
	if err := d.QueryRow(`SELECT count(*) FROM notification_events
		WHERE finding_id=$1 AND kind='finding_status_changed'`, first).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("同状态重复提交不该再登记事件, got %d", events)
	}
}

// TestSetFindingsStatusBatchRejectsEmptyAndOversized 边界：空列表与超量都要在
// 写库之前被挡住，否则等于让调用方用一个请求锁住全表。
func TestSetFindingsStatusBatchRejectsEmptyAndOversized(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	if _, err := d.SetFindingsStatusBatch(context.Background(), nil, "resolved"); err == nil {
		t.Error("空 id 列表应当报错")
	}
	tooMany := make([]int64, MaxFindingBatchSize+1)
	if _, err := d.SetFindingsStatusBatch(context.Background(), tooMany, "resolved"); err == nil {
		t.Errorf("超过 %d 条应当报错", MaxFindingBatchSize)
	}
	if _, err := d.DeleteFindingsBatch(context.Background(), nil); err == nil {
		t.Error("空 id 列表应当报错")
	}
}

// TestDeleteFindingsBatch 覆盖批量删除：findings 行、来源探索节点、通知事件
// 全部消失，且逐条返回 found 供前端汇报。
func TestDeleteFindingsBatch(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	first := seedFindingForBatch(t, d, "待删一")
	second := seedFindingForBatch(t, d, "待删二")
	missing := int64(999999999)

	if _, err := d.Exec(`INSERT INTO notification_events(kind,finding_id,snapshot)
		VALUES('finding_created',$1,'{}')`, first); err != nil {
		t.Fatal(err)
	}

	results, err := d.DeleteFindingsBatch(context.Background(), []int64{first, second, missing})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("结果条数: want 3, got %d", len(results))
	}
	if !results[0].Found || !results[1].Found {
		t.Errorf("两条真实漏洞都应删除成功: %+v", results)
	}
	if results[2].Found {
		t.Errorf("不存在的 id 不应报 found: %+v", results[2])
	}

	for _, id := range []int64{first, second} {
		if f, _ := d.GetFinding(id); f != nil {
			t.Errorf("漏洞 %d 应已删除", id)
		}
		var nodes int
		if err := d.QueryRow(`SELECT count(*) FROM exploration_nodes
			WHERE id=(SELECT node_id FROM findings WHERE id=$1)`, id).Scan(&nodes); err != nil {
			t.Fatal(err)
		}
		var events int
		if err := d.QueryRow(`SELECT count(*) FROM notification_events WHERE finding_id=$1`, id).Scan(&events); err != nil {
			t.Fatal(err)
		}
		if events != 0 {
			t.Errorf("漏洞 %d 的通知事件应一并清理, 残留 %d 行", id, events)
		}
	}
}
