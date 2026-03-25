package workflow

import (
	"encoding/json"
	"fmt"
	"time"
)

// FindingStatus represents the lifecycle state of a finding.
type FindingStatus string

const (
	StatusNew         FindingStatus = "new"
	StatusTriaged     FindingStatus = "triaged"
	StatusAssigned    FindingStatus = "assigned"
	StatusInProgress  FindingStatus = "in_progress"
	StatusInReview    FindingStatus = "in_review"
	StatusFixed       FindingStatus = "fixed"
	StatusVerified    FindingStatus = "verified"
	StatusWontFix     FindingStatus = "wont_fix"
	StatusFalsePos    FindingStatus = "false_positive"
	StatusAccepted    FindingStatus = "accepted_risk"
)

// ValidTransitions defines the state machine.
var ValidTransitions = map[FindingStatus][]FindingStatus{
	StatusNew:        {StatusTriaged, StatusFalsePos},
	StatusTriaged:    {StatusAssigned, StatusWontFix, StatusFalsePos},
	StatusAssigned:   {StatusInProgress, StatusWontFix},
	StatusInProgress: {StatusInReview, StatusAssigned},
	StatusInReview:   {StatusFixed, StatusInProgress},
	StatusFixed:      {StatusVerified, StatusInProgress},
	StatusVerified:   {},
	StatusWontFix:    {StatusTriaged},
	StatusFalsePos:   {StatusTriaged},
	StatusAccepted:   {StatusTriaged},
}

// FindingEvent records a state change or action on a finding.
type FindingEvent struct {
	ID         string        `json:"id"`
	FindingID  string        `json:"finding_id"`
	EventType  string        `json:"event_type"` // "status_change", "assignment", "comment", "sla_breach"
	FromStatus FindingStatus `json:"from_status,omitempty"`
	ToStatus   FindingStatus `json:"to_status,omitempty"`
	Actor      string        `json:"actor"`
	Details    string        `json:"details,omitempty"`
	Timestamp  time.Time     `json:"timestamp"`
}

// SLAPolicy defines fix deadlines by severity.
type SLAPolicy struct {
	CriticalDays int `json:"critical_days"` // default 14
	HighDays     int `json:"high_days"`     // default 30
	MediumDays   int `json:"medium_days"`   // default 90
	LowDays      int `json:"low_days"`      // default 180
}

// DefaultSLA returns sensible SLA defaults.
func DefaultSLA() SLAPolicy {
	return SLAPolicy{CriticalDays: 14, HighDays: 30, MediumDays: 90, LowDays: 180}
}

// FindingState tracks the current state of a finding in the workflow.
type FindingState struct {
	FindingID   string        `json:"finding_id"`
	Status      FindingStatus `json:"status"`
	Assignee    string        `json:"assignee,omitempty"`
	FixCommit   string        `json:"fix_commit,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
	SLADeadline time.Time     `json:"sla_deadline"`
	SLABreached bool          `json:"sla_breached"`
	Events      []FindingEvent `json:"events"`
}

// WorkflowManager manages finding lifecycle states.
type WorkflowManager struct {
	states map[string]*FindingState // findingID → state
	sla    SLAPolicy
}

// NewWorkflowManager creates a workflow manager.
func NewWorkflowManager(sla ...SLAPolicy) *WorkflowManager {
	s := DefaultSLA()
	if len(sla) > 0 { s = sla[0] }
	return &WorkflowManager{states: make(map[string]*FindingState), sla: s}
}

// InitFinding creates initial state for a finding.
func (wm *WorkflowManager) InitFinding(findingID string, severity int) *FindingState {
	days := wm.sla.LowDays
	switch severity {
	case 0: days = wm.sla.CriticalDays
	case 1: days = wm.sla.HighDays
	case 2: days = wm.sla.MediumDays
	}
	now := time.Now()
	state := &FindingState{
		FindingID:   findingID,
		Status:      StatusNew,
		CreatedAt:   now,
		UpdatedAt:   now,
		SLADeadline: now.AddDate(0, 0, days),
	}
	wm.states[findingID] = state
	return state
}

// Transition moves a finding to a new state.
func (wm *WorkflowManager) Transition(findingID string, newStatus FindingStatus, actor, details string) error {
	state, ok := wm.states[findingID]
	if !ok { return fmt.Errorf("finding %s not found", findingID) }

	valid := false
	for _, allowed := range ValidTransitions[state.Status] {
		if allowed == newStatus { valid = true; break }
	}
	if !valid {
		return fmt.Errorf("invalid transition: %s → %s", state.Status, newStatus)
	}

	event := FindingEvent{
		ID: fmt.Sprintf("evt-%s-%d", findingID, len(state.Events)),
		FindingID: findingID, EventType: "status_change",
		FromStatus: state.Status, ToStatus: newStatus,
		Actor: actor, Details: details, Timestamp: time.Now(),
	}
	state.Events = append(state.Events, event)
	state.Status = newStatus
	state.UpdatedAt = time.Now()
	return nil
}

// Assign assigns a finding to a developer.
func (wm *WorkflowManager) Assign(findingID, assignee, actor string) error {
	state, ok := wm.states[findingID]
	if !ok { return fmt.Errorf("finding %s not found", findingID) }
	state.Assignee = assignee
	if state.Status == StatusTriaged || state.Status == StatusNew {
		state.Status = StatusAssigned
	}
	state.Events = append(state.Events, FindingEvent{
		FindingID: findingID, EventType: "assignment",
		Actor: actor, Details: fmt.Sprintf("Assigned to %s", assignee),
		Timestamp: time.Now(),
	})
	state.UpdatedAt = time.Now()
	return nil
}

// Comment adds a comment to a finding.
func (wm *WorkflowManager) Comment(findingID, actor, text string) error {
	state, ok := wm.states[findingID]
	if !ok { return fmt.Errorf("finding %s not found", findingID) }
	state.Events = append(state.Events, FindingEvent{
		FindingID: findingID, EventType: "comment",
		Actor: actor, Details: text, Timestamp: time.Now(),
	})
	return nil
}

// CheckSLABreaches returns findings that have breached their SLA.
func (wm *WorkflowManager) CheckSLABreaches() []FindingState {
	var breached []FindingState
	now := time.Now()
	for _, s := range wm.states {
		if s.Status != StatusFixed && s.Status != StatusVerified &&
			s.Status != StatusWontFix && s.Status != StatusFalsePos &&
			now.After(s.SLADeadline) {
			s.SLABreached = true
			breached = append(breached, *s)
		}
	}
	return breached
}

// GetState returns the current state of a finding.
func (wm *WorkflowManager) GetState(findingID string) (*FindingState, bool) {
	s, ok := wm.states[findingID]
	return s, ok
}

// MigrationProgress computes overall migration progress.
type MigrationProgress struct {
	TotalFindings   int     `json:"total_findings"`
	Fixed           int     `json:"fixed"`
	Verified        int     `json:"verified"`
	InProgress      int     `json:"in_progress"`
	Remaining       int     `json:"remaining"`
	ProgressPct     float64 `json:"progress_percent"`
	AvgFixTimeHours float64 `json:"avg_fix_time_hours"`
	SLABreaches     int     `json:"sla_breaches"`
}

// GetProgress computes migration progress across all findings.
func (wm *WorkflowManager) GetProgress() MigrationProgress {
	p := MigrationProgress{TotalFindings: len(wm.states)}
	var fixTimes []float64
	for _, s := range wm.states {
		switch s.Status {
		case StatusFixed: p.Fixed++
		case StatusVerified: p.Verified++
		case StatusInProgress, StatusInReview: p.InProgress++
		}
		if s.SLABreached { p.SLABreaches++ }
		if s.Status == StatusFixed || s.Status == StatusVerified {
			fixTimes = append(fixTimes, s.UpdatedAt.Sub(s.CreatedAt).Hours())
		}
	}
	p.Remaining = p.TotalFindings - p.Fixed - p.Verified
	if p.TotalFindings > 0 {
		p.ProgressPct = float64(p.Fixed+p.Verified) / float64(p.TotalFindings) * 100
	}
	if len(fixTimes) > 0 {
		sum := 0.0
		for _, t := range fixTimes { sum += t }
		p.AvgFixTimeHours = sum / float64(len(fixTimes))
	}
	return p
}

// ToJSON serializes any workflow object.
func ToJSON(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
