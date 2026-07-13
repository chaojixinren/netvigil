package tic

import (
	"log"

	"github.com/saurlax/netvigil/util"
)

// AILocal represents a local AI-based threat detection using ONNX model
type AILocal struct{}

func (a *AILocal) Check(netstats []*util.Netstat) []util.Result {
	var results []util.Result

	for _, ns := range netstats {
		// Check if packet is anomalous using local AI model
		isAnomaly := util.Check(ns.Packet)

		if isAnomaly {
			threat := util.Threat{
				Time:        ns.Time,
				IP:          ns.DstIP,
				TIC:         "ai-local",
				Reason:      "本地AI模型检测到异常流量特征",
				Risk:        util.Suspicious,
				Credibility: util.Medium,
			}

			results = append(results, util.Result{
				Time:    ns.Time,
				IP:      ns.DstIP,
				Netstat: ns,
				Threat:  &threat,
			})

			log.Printf("[AI-Local] Anomaly detected: %s -> %s (Confidence: High)\n", ns.SrcIP, ns.DstIP)
		}
	}

	if len(results) > 0 {
		log.Printf("[AI-Local] Detected %d anomalies\n", len(results))
	}

	return results
}
