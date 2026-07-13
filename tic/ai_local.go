package tic

import (
	"fmt"
	"log"

	"github.com/saurlax/netvigil/util"
)

// AILocal represents a local AI-based threat detection using ONNX model
type AILocal struct {
	// Threshold 异常判定阈值 [0,1]：模型给出的异常概率达到该值才判定为威胁。
	Threshold float64
}

func (a *AILocal) Check(netstats []*util.Netstat) []util.Result {
	var results []util.Result

	for _, ns := range netstats {
		// 模型返回该包的异常概率；ok=false 表示模型不可用或推理失败，直接跳过。
		prob, ok := util.Check(ns.Packet)
		if !ok {
			continue
		}

		// 只有异常概率达到配置阈值才判定为威胁。
		if float64(prob) < a.Threshold {
			continue
		}

		risk, credibility := classifyByProb(prob)
		threat := util.Threat{
			Time:        ns.Time,
			IP:          ns.DstIP,
			TIC:         "ai-local",
			Reason:      fmt.Sprintf("本地AI模型检测到异常流量特征 (异常概率 %.1f%%)", prob*100),
			Risk:        risk,
			Credibility: credibility,
		}

		results = append(results, util.Result{
			Time:    ns.Time,
			IP:      ns.DstIP,
			Netstat: ns,
			Threat:  &threat,
		})

		log.Printf("[AI-Local] Anomaly detected: %s -> %s (prob=%.2f, threshold=%.2f)\n",
			ns.SrcIP, ns.DstIP, prob, a.Threshold)
	}

	if len(results) > 0 {
		log.Printf("[AI-Local] Detected %d anomalies\n", len(results))
	}

	return results
}

// classifyByProb 根据模型给出的异常概率映射风险等级与可信度：
// 概率越高，风险与可信度越高。
func classifyByProb(prob float32) (util.RiskLevel, util.CredibilityLevel) {
	switch {
	case prob >= 0.9:
		return util.Malicious, util.High
	case prob >= 0.8:
		return util.Suspicious, util.High
	default:
		return util.Suspicious, util.Medium
	}
}
