package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 票据 01：OOB 配置接线测试。默认启用+公共服务；可配自建地址与 token；
// 启用但地址为空且用户显式写了 oob 块 → 明确失败（不静默回退）。

func TestOOBOptionsDefaults(t *testing.T) {
	t.Setenv("ARTEX_CONFIG", filepath.Join(t.TempDir(), "absent.json"))
	r := OOBOptions().Resolve()
	if !r.Enabled {
		t.Fatal("默认应启用 OOB")
	}
	if r.ServerURL == "" || !strings.Contains(r.ServerURL, "oast.") {
		t.Fatalf("默认应为公共服务: %q", r.ServerURL)
	}
}

func TestOOBOptionsSelfHosted(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"oob":{"enabled":true,"server_url":"https://oob.example.com","token":"tok"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CONFIG", cfgPath)
	r := OOBOptions().Resolve()
	if !r.Enabled || r.ServerURL != "https://oob.example.com" || r.Token != "tok" {
		t.Fatalf("自建配置未生效: %+v", r)
	}
}

func TestOOBOptionsDisabled(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"oob":{"enabled":false}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CONFIG", cfgPath)
	if r := OOBOptions().Resolve(); r.Enabled {
		t.Fatal("enabled:false 应关闭 OOB")
	}
}

func TestOOBOptionsExplicitEmptyServerDoesNotFallBack(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"oob":{"enabled":true,"server_url":""}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CONFIG", cfgPath)
	r := OOBOptions().Resolve()
	if !r.Enabled {
		t.Fatal("显式 enabled:true 应保持启用")
	}
	if r.ServerURL != "" {
		t.Fatalf("显式空 server_url 不得静默回退公共服务: %q", r.ServerURL)
	}
}

func TestOOBOptionsExplicitEmptyBlockDoesNotFallBack(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"oob":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CONFIG", cfgPath)
	if r := OOBOptions().Resolve(); r.ServerURL != "" {
		t.Fatalf("显式 oob 块缺少 server_url 不得静默回退公共服务: %q", r.ServerURL)
	}
}
