package utils

import (
	"context"

	meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	extv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
)

// recomputes the aggregate Ready condition from current Status.Conditions,
// sets it, and stamps ObservedGeneration.
func RecomputeReadyInPlace(obx *extv1alpha1.OpenBaoExtension) {
	s, reason, msg := ComputeReady(obx.Status.Conditions)
	SetCond(&obx.Status.Conditions, extv1alpha1.CondReady, s, reason, msg)
	if c := FindCond(obx.Status.Conditions, extv1alpha1.CondReady); c != nil {
		c.ObservedGeneration = obx.GetGeneration()
	}
}

// RecomputeReadyAndPatch fetches latest, recomputes Ready, and patches /status.
func RecomputeReadyAndPatch(ctx context.Context, c client.Client, key types.NamespacedName) error {
	var cur extv1alpha1.OpenBaoExtension
	if err := c.Get(ctx, key, &cur); err != nil {
		return client.IgnoreNotFound(err)
	}
	orig := cur.DeepCopy()
	RecomputeReadyInPlace(&cur)
	return c.Status().Patch(ctx, &cur, client.MergeFrom(orig))
}

// SetCond updates or inserts a metav1.Condition.
func SetCond(conds *[]metav1.Condition, typ string, st metav1.ConditionStatus, reason, msg string) {
	meta.SetStatusCondition(conds, metav1.Condition{
		Type:    typ,
		Status:  st,
		Reason:  reason,
		Message: msg,
	})
}

func FindCond(conds []metav1.Condition, typ string) *metav1.Condition {
	return meta.FindStatusCondition(conds, typ)
}

func ComputeReady(conds []metav1.Condition) (metav1.ConditionStatus, string, string) {
	auth := FindCond(conds, extv1alpha1.CondAuthConfigured)
	ten := FindCond(conds, extv1alpha1.CondTenantsReconciled)

	if auth == nil || ten == nil || auth.Status == metav1.ConditionUnknown || ten.Status == metav1.ConditionUnknown {
		return metav1.ConditionUnknown, extv1alpha1.ReasonWaitingDependencies, "Waiting for sub-conditions."
	}
	if auth.Status == metav1.ConditionTrue && ten.Status == metav1.ConditionTrue {
		return metav1.ConditionTrue, extv1alpha1.ReasonSuccess, "All dependencies healthy."
	}
	if (auth != nil && auth.Reason == extv1alpha1.ReasonError) || (ten != nil && ten.Reason == extv1alpha1.ReasonError) {
		return metav1.ConditionFalse, extv1alpha1.ReasonError, "Dependency error."
	}
	return metav1.ConditionFalse, extv1alpha1.ReasonWaitingDependencies, "Dependencies not ready."
}
