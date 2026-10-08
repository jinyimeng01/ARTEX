package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/Autumn-27/artex/db"
)

// maxFindingBatchRequestBytes 限制批量请求的正文大小。
//
// 200 条 id 的 JSON 也就几 KB，这个上限是防「id 数组塞进几十万个元素」把
// 解析器的内存吃光，与条目数上限 db.MaxFindingBatchSize 各管一头。
const maxFindingBatchRequestBytes = 64 << 10

// decodeFindingBatch 解析批量请求体，返回去重后的漏洞 id 与原始 status 字段。
//
// status 只在改状态时必填，由调用方判断；删除路径忽略它即可，这样两个接口
// 共用同一个请求体形状，前端多选工具栏也能复用同一套序列化逻辑。
//
// 返回 false 时已经写过错误响应，调用方直接 return。
func decodeFindingBatch(w http.ResponseWriter, r *http.Request) ([]int64, string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFindingBatchRequestBytes)
	var request struct {
		FindingIDs []int64         `json:"finding_ids"`
		Status     json.RawMessage `json:"status"`
	}
	if err := decode(r, &request); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return nil, "", false
	}
	ids := normalizeFindingBatchIDs(request.FindingIDs)
	if len(ids) == 0 || len(ids) > db.MaxFindingBatchSize {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("finding_ids 数量必须为 1-%d", db.MaxFindingBatchSize))
		return nil, "", false
	}
	status := ""
	if len(request.Status) > 0 {
		if err := json.Unmarshal(request.Status, &status); err != nil {
			writeErr(w, http.StatusBadRequest, "bad status: "+err.Error())
			return nil, "", false
		}
	}
	return ids, status, true
}

// normalizeFindingBatchIDs 去掉非正数与重复项。
//
// 去重是必要的：同一条漏洞出现两次时，改状态路径第二次会读到「已经是目标状态」
// 而返回 changed=false，删除路径则会因为行已不存在而静默少删一条，两种结果
// 都对用户没有意义。前端重复勾选不应该在响应里表现为一条成功一条 no-op。
func normalizeFindingBatchIDs(ids []int64) []int64 {
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// batchFindingResponse 是两个批量接口共用的响应形状。
type batchFindingResponse struct {
	Results []db.BatchFindingStatusResult `json:"results"`
	// Updated/Deleted 是「真的发生了变化」的条数，Skipped 是不存在或本就同状态的
	// 条数。前端用它弹成功提示，不用自己数 results 数组。
	Updated int `json:"updated,omitempty"`
	Deleted int `json:"deleted,omitempty"`
	Skipped int `json:"skipped,omitempty"`
}

// patchFindingsBatch 把多条漏洞改到同一状态，逐条登记状态变更推送事件。
//
// 响应始终是 200 + 逐条结果：不存在或状态本就相同的漏洞记 found=false /
// changed=false 而不是报错，否则前端没法告诉用户「勾了 10 条，实际改了 7 条」。
// 真正失败（DB 错误）才走 5xx——那种情况下整个事务已回滚，一条都没改成。
func (s *Server) patchFindingsBatch(w http.ResponseWriter, r *http.Request) {
	ids, status, ok := decodeFindingBatch(w, r)
	if !ok {
		return
	}
	if status == "" {
		writeErr(w, http.StatusBadRequest, "status 不能为空")
		return
	}
	if !db.ValidFindingStatus(status) {
		writeErr(w, http.StatusBadRequest, "bad status: "+status)
		return
	}
	results, err := s.m.pg.SetFindingsStatusBatch(r.Context(), ids, status)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := batchFindingResponse{Results: results}
	for _, item := range results {
		switch {
		case item.Found && item.Changed:
			resp.Updated++
			if !item.Notified {
				log.Printf("[notify] 批量状态变更事件未登记 finding=%d %s→%s（状态已更新）", item.ID, item.From, status)
			}
		default:
			resp.Skipped++
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// deleteFindingsBatch 删除多条漏洞：findings 行、来源 kind='finding' 探索节点、
// 该漏洞的通知事件，以及由事件级联的投递行。
//
// 与 patchFindingsBatch 一样逐条返回、不因单条不存在而整体报错。
func (s *Server) deleteFindingsBatch(w http.ResponseWriter, r *http.Request) {
	ids, _, ok := decodeFindingBatch(w, r)
	if !ok {
		return
	}
	results, err := s.m.pg.DeleteFindingsBatch(r.Context(), ids)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	resp := batchFindingResponse{Results: results}
	for _, item := range results {
		if item.Found {
			resp.Deleted++
		} else {
			resp.Skipped++
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
