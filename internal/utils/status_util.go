package utils

import (
	"time"

	extv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//nolint:unparam // keep typ flexible for future condition types
func SetCondGen(ext *extv1alpha1.OpenBaoExtension, typ string, st metav1.ConditionStatus, reason, msg string) {
	setCond(&ext.Status.Conditions, typ, st, reason, msg)
	if c := findCond(ext.Status.Conditions, typ); c != nil {
		c.ObservedGeneration = ext.GetGeneration()
	}
}

// remove condition entries of a given type to avoid stale failures persisting
//
//nolint:unparam // keep typ flexible for future condition types
func RemoveCondGen(ext *extv1alpha1.OpenBaoExtension, typ string) {
	conds := ext.Status.Conditions
	out := conds[:0]
	for i := range conds {
		if conds[i].Type != typ {
			out = append(out, conds[i])
		}
	}
	ext.Status.Conditions = out
}

// --- internal helpers (inlined so this util is standalone) ---

func setCond(conds *[]metav1.Condition, typ string, st metav1.ConditionStatus, reason, msg string) {
	now := metav1.NewTime(time.Now())

	if c := findCond(*conds, typ); c != nil {
		if c.Status != st {
			c.LastTransitionTime = now
		}
		c.Status = st
		c.Reason = reason
		c.Message = msg
		return
	}

	*conds = append(*conds, metav1.Condition{
		Type:               typ,
		Status:             st,
		Reason:             reason,
		Message:            msg,
		LastTransitionTime: now,
	})
}

func findCond(conds []metav1.Condition, typ string) *metav1.Condition {
	for i := range conds {
		if conds[i].Type == typ {
			return &conds[i]
		}
	}
	return nil
}
