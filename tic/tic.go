package tic

import (
	"log"
	"time"

	"github.com/saurlax/netvigil/util"
	"github.com/spf13/viper"
)

// Threat Intelligence Center
type TIC interface {
	Check(netstats []*util.Netstat) []util.Result
}

var tics = make([]TIC, 0)

// create a TIC instance with config
func create(m map[string]any) TIC {
	switch m["type"] {
	case "local":
		return &Local{}
	case "ai-local":
		// 默认阈值 0.7，可被配置覆盖；兼容 toml 解析出的 float64/int/int64。
		threshold := 0.7
		switch t := m["threshold"].(type) {
		case float64:
			threshold = t
		case int:
			threshold = float64(t)
		case int64:
			threshold = float64(t)
		}
		log.Printf("[TIC] ai-local threshold set to %.2f\n", threshold)
		return &AILocal{Threshold: threshold}
	case "threatbook":
		return &Threatbook{
			APIKey: m["apikey"].(string),
		}
	case "netvigil":
		return &Netvigil{
			Server: m["server"].(string),
			APIKey: m["apikey"].(string),
		}
	default:
		return nil
	}
}

// check netstats via all TICs
func CheckAll() []*util.Result {
	var netstats []*util.Netstat
	var results []*util.Result
	for len(util.Netstats) > 0 {
		ns := <-util.Netstats
		netstats = append(netstats, &ns)
	}

	for _, tic := range tics {
		for _, res := range tic.Check(netstats) {
			results = append(results, &res)
			// remove the netstat that has been checked
			filtered := make([]*util.Netstat, 0)
			for _, ns := range netstats {
				if ns.DstIP != res.IP {
					filtered = append(filtered, ns)
				}
			}
			netstats = filtered
		}
	}

	for _, ns := range netstats {
		results = append(results, &util.Result{
			Time:    time.Now().Unix(),
			IP:      ns.DstIP,
			Netstat: ns,
			Threat:  nil,
		})
	}

	return results
}

func init() {
	log.Println("[TIC] check period:", viper.GetDuration("check_period"))
	config := viper.Get("tic").([]any)
	for _, v := range config {
		m, ok := v.(map[string]any)
		if !ok {
			break
		}
		tic := create(m)
		if tic != nil {
			log.Printf("[TIC] %s created\n", m["type"])
			tics = append(tics, tic)
		}
	}
}
