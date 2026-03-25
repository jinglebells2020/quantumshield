package workflow

import "testing"

func TestInitFinding(t *testing.T) {
	wm := NewWorkflowManager()
	state := wm.InitFinding("f-001", 0) // critical
	if state.Status != StatusNew {
		t.Errorf("expected new, got %s", state.Status)
	}
	if state.SLADeadline.IsZero() {
		t.Error("SLA deadline should be set")
	}
}

func TestTransition_Valid(t *testing.T) {
	wm := NewWorkflowManager()
	wm.InitFinding("f-001", 0)
	if err := wm.Transition("f-001", StatusTriaged, "admin", ""); err != nil {
		t.Errorf("valid transition failed: %v", err)
	}
	s, _ := wm.GetState("f-001")
	if s.Status != StatusTriaged {
		t.Errorf("expected triaged, got %s", s.Status)
	}
}

func TestTransition_Invalid(t *testing.T) {
	wm := NewWorkflowManager()
	wm.InitFinding("f-001", 0)
	err := wm.Transition("f-001", StatusFixed, "admin", "") // can't go New->Fixed
	if err == nil {
		t.Error("expected error for invalid transition")
	}
}

func TestAssign(t *testing.T) {
	wm := NewWorkflowManager()
	wm.InitFinding("f-001", 1)
	wm.Transition("f-001", StatusTriaged, "admin", "")
	wm.Assign("f-001", "dev@co.com", "admin")
	s, _ := wm.GetState("f-001")
	if s.Assignee != "dev@co.com" {
		t.Errorf("expected dev@co.com, got %s", s.Assignee)
	}
	if s.Status != StatusAssigned {
		t.Errorf("expected assigned, got %s", s.Status)
	}
}

func TestComment(t *testing.T) {
	wm := NewWorkflowManager()
	wm.InitFinding("f-001", 0)
	wm.Comment("f-001", "dev", "Working on it")
	s, _ := wm.GetState("f-001")
	if len(s.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(s.Events))
	}
}

func TestGetProgress(t *testing.T) {
	wm := NewWorkflowManager()
	wm.InitFinding("f-001", 0)
	wm.InitFinding("f-002", 1)
	wm.InitFinding("f-003", 2)
	wm.Transition("f-001", StatusTriaged, "a", "")
	wm.Transition("f-001", StatusAssigned, "a", "")
	wm.Transition("f-001", StatusInProgress, "a", "")
	wm.Transition("f-001", StatusInReview, "a", "")
	wm.Transition("f-001", StatusFixed, "a", "")
	p := wm.GetProgress()
	if p.TotalFindings != 3 {
		t.Errorf("expected 3 total, got %d", p.TotalFindings)
	}
	if p.Fixed != 1 {
		t.Errorf("expected 1 fixed, got %d", p.Fixed)
	}
	if p.ProgressPct < 30 {
		t.Errorf("expected ~33%%, got %.1f%%", p.ProgressPct)
	}
}

func TestSLABreach(t *testing.T) {
	wm := NewWorkflowManager(SLAPolicy{CriticalDays: 0, HighDays: 0, MediumDays: 0, LowDays: 0})
	wm.InitFinding("f-001", 0)
	breached := wm.CheckSLABreaches()
	if len(breached) != 1 {
		t.Errorf("expected 1 breach, got %d", len(breached))
	}
}
