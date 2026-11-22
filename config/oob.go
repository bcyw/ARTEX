package config

import (
	"encoding/json"
	"os"
)

// OOB (Interactsh) configuration. Shipped defaults: enabled against the public
// official service; a self-hosted server_url + token can be set in config.json.
// 显式启用但地址为空 → OOBOptions 返回的配置在 agent.OOBSessionFactory 处明确报错，
// 不静默回退到公共服务。

// OOB is the on-disk "oob" config block.
type OOB struct {
	Enabled   *bool  `json:"enabled"` // nil = default true
	ServerURL string `json:"server_url"`
	Token     string `json:"token"`
}

// oobDefaultURL is the official public Interactsh servers (same list as the
// upstream client default).
const oobDefaultURL = "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me"

// OOBOptions resolves the OOB config with defaults applied. Only a config
// without an "oob" block selects the public default; an explicit block is
// returned as written so an empty/cleartext server_url fails validation
// instead of silently moving probe traffic to the public service.
func OOBOptions() OOB {
	var raw struct {
		OOBBlock *OOB `json:"oob"`
	}
	if b, err := os.ReadFile(Path()); err == nil && json.Unmarshal(b, &raw) == nil && raw.OOBBlock != nil {
		return *raw.OOBBlock
	}
	return OOB{ServerURL: oobDefaultURL}
}

// Resolved is the dereferenced, default-applied OOB configuration.
type Resolved struct {
	Enabled   bool
	ServerURL string
	Token     string
}

// Resolve applies the enabled default (nil = true) and returns concrete values.
func (c OOB) Resolve() Resolved {
	enabled := c.Enabled == nil || *c.Enabled
	return Resolved{Enabled: enabled, ServerURL: c.ServerURL, Token: c.Token}
}
