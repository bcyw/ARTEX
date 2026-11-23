package db

import (
	"reflect"
	"testing"
)

// builtinTaskTemplateNames are the shipped presets seeded on every startup.
var builtinTaskTemplateNames = []string{"单域名全量渗透", "批量资产全量渗透", "资产梳理"}

// mustOpenSeed opens a fresh temp DB (schema + seeds applied, same as startup).
func mustOpenSeed(t *testing.T) *DB {
	t.Helper()
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatalf("open temp db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func findTaskTemplate(t *testing.T, d *DB, name string) *TaskTemplate {
	t.Helper()
	templates, err := d.ListTaskTemplates()
	if err != nil {
		t.Fatalf("list templates: %v", err)
	}
	for _, template := range templates {
		if template.Name == name {
			return template
		}
	}
	return nil
}

func findTaskCategory(t *testing.T, d *DB, name string) *TaskCategory {
	t.Helper()
	categories, err := d.ListTaskCategories()
	if err != nil {
		t.Fatalf("list categories: %v", err)
	}
	for _, category := range categories {
		if category.Name == name {
			return category
		}
	}
	return nil
}

// TestSeedTaskTemplates verifies the three shipped presets exist on a fresh DB,
// carry non-empty description/goal, and are linked to their seeded categories.
func TestSeedTaskTemplates(t *testing.T) {
	d := mustOpenSeed(t)

	for _, name := range builtinTaskTemplateNames {
		template := findTaskTemplate(t, d, name)
		if template == nil {
			t.Fatalf("builtin template %q missing after seed", name)
		}
		if template.Description == "" || template.Goal == "" {
			t.Fatalf("builtin template %q has empty description/goal: %+v", name, template)
		}
		if template.CategoryID == nil {
			t.Fatalf("builtin template %q has no category", name)
		}
		if got := findTaskCategory(t, d, "渗透测试"); name != "资产梳理" && got == nil {
			t.Fatalf("category %q missing", "渗透测试")
		}
	}
	if got := findTaskCategory(t, d, "资产梳理"); got == nil {
		t.Fatal(`category "资产梳理" missing`)
	}
}

// TestSeedTaskTemplatesIdempotent asserts a second seed run neither duplicates
// nor overwrites: edited templates keep their edits, deleted ones are re-seeded.
func TestSeedTaskTemplatesIdempotent(t *testing.T) {
	d := mustOpenSeed(t)

	edited := findTaskTemplate(t, d, "单域名全量渗透")
	if edited == nil {
		t.Fatal("template to edit missing")
	}
	deleted := findTaskTemplate(t, d, "资产梳理")
	if deleted == nil {
		t.Fatal("template to delete missing")
	}

	newGoal := "用户自定义的目标文案"
	if _, err := d.PatchTaskTemplate(edited.ID, TaskTemplatePatch{Goal: &newGoal}); err != nil {
		t.Fatalf("patch template: %v", err)
	}
	if _, err := d.DeleteTaskTemplate(deleted.ID); err != nil {
		t.Fatalf("delete template: %v", err)
	}

	if err := d.seedTaskTemplates(); err != nil {
		t.Fatalf("re-seed: %v", err)
	}

	if got := findTaskTemplate(t, d, "单域名全量渗透"); got == nil || got.Goal != newGoal {
		t.Fatalf("re-seed overwrote user edit: %+v", got)
	}
	if got := findTaskTemplate(t, d, "资产梳理"); got == nil {
		t.Fatal("re-seed did not restore deleted builtin template")
	}

	templates, err := d.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	for _, template := range templates {
		for _, name := range builtinTaskTemplateNames {
			if template.Name == name {
				count++
			}
		}
	}
	if count != len(builtinTaskTemplateNames) {
		t.Fatalf("re-seeded builtin templates = %d, want %d (no duplicates)", count, len(builtinTaskTemplateNames))
	}
}

// A fresh process must preserve customized presets.
func TestSeedTaskTemplatesUserEditNotClobbered(t *testing.T) {
	dsn := testDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	newGoal := "用户自定义的目标文案"
	if template := findTaskTemplate(t, d, "批量资产全量渗透"); template != nil {
		if _, err := d.PatchTaskTemplate(template.ID, TaskTemplatePatch{Goal: &newGoal}); err != nil {
			t.Fatalf("patch: %v", err)
		}
	} else {
		t.Fatal("template missing after first open")
	}
	d.Close()

	d2, err := Open(dsn)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer d2.Close()
	if got := findTaskTemplate(t, d2, "批量资产全量渗透"); got == nil || got.Goal != newGoal {
		t.Fatalf("second open overwrote user edit: %+v", got)
	}
}

func TestSeedTaskTemplatesUpgradeLegacyDefaults(t *testing.T) {
	dsn := testDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	previous := make(map[string]*TaskTemplate)
	for name, goal := range legacyTaskTemplateGoals {
		template := findTaskTemplate(t, d, name)
		if template == nil {
			t.Fatalf("missing template %q", name)
		}
		previous[name], err = d.PatchTaskTemplate(template.ID, TaskTemplatePatch{Goal: &goal})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	upgraded, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	for _, preset := range builtinTaskTemplates {
		got := findTaskTemplate(t, upgraded, preset.Name)
		old := previous[preset.Name]
		if got == nil || old == nil || got.ID != old.ID || got.Goal != preset.Goal ||
			got.Description != old.Description || !reflect.DeepEqual(got.CategoryID, old.CategoryID) ||
			!got.CreatedAt.Equal(old.CreatedAt) {
			t.Fatalf("legacy preset %q not upgraded in place: old=%+v got=%+v", preset.Name, old, got)
		}
	}
	before, err := upgraded.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if err := upgraded.seedTaskTemplates(); err != nil {
		t.Fatal(err)
	}
	after, err := upgraded.ListTaskTemplates()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("re-seeding changed already upgraded templates")
	}
}

func TestSeedTaskTemplatesPreserveLegacyCustomization(t *testing.T) {
	for _, field := range []string{"goal", "description", "category", "no category", "name"} {
		t.Run(field, func(t *testing.T) {
			d := mustOpenSeed(t)
			preset := builtinTaskTemplates[0]
			template := findTaskTemplate(t, d, preset.Name)
			if template == nil {
				t.Fatal("missing template")
			}
			goal := legacyTaskTemplateGoals[preset.Name]
			if _, err := d.PatchTaskTemplate(template.ID, TaskTemplatePatch{Goal: &goal}); err != nil {
				t.Fatal(err)
			}
			var patch TaskTemplatePatch
			custom := "用户自定义内容"
			switch field {
			case "goal":
				patch.Goal = &custom
			case "description":
				patch.Description = &custom
			case "category":
				category, err := d.CreateTaskCategory(custom)
				if err != nil {
					t.Fatal(err)
				}
				patch.CategoryID, patch.SetCategoryID = &category.ID, true
			case "no category":
				patch.SetCategoryID = true
			case "name":
				patch.Name = &custom
			}
			if _, err := d.PatchTaskTemplate(template.ID, patch); err != nil {
				t.Fatal(err)
			}
			before, err := d.GetTaskTemplate(template.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.seedTaskTemplates(); err != nil {
				t.Fatal(err)
			}
			after, err := d.GetTaskTemplate(template.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("legacy %s customization overwritten: before=%+v after=%+v", field, before, after)
			}
		})
	}
}
