package utils

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	extv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
)

func Test_ComputeReady_TruthTable(t *testing.T) {
	tcs := []struct {
		name       string
		auth, ten  metav1.ConditionStatus // empty == missing
		wantStatus metav1.ConditionStatus
		wantReason string
	}{
		{"unknown_when_any_unknown", metav1.ConditionUnknown, metav1.ConditionTrue, metav1.ConditionUnknown, extv1alpha1.ReasonWaitingDependencies},
		{"unknown_when_missing_leaf", metav1.ConditionTrue, metav1.ConditionStatus(""), metav1.ConditionUnknown, extv1alpha1.ReasonWaitingDependencies},
		{"false_when_any_false", metav1.ConditionTrue, metav1.ConditionFalse, metav1.ConditionFalse, extv1alpha1.ReasonWaitingDependencies},
		{"true_when_both_true", metav1.ConditionTrue, metav1.ConditionTrue, metav1.ConditionTrue, extv1alpha1.ReasonSuccess},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var conds []metav1.Condition
			if tc.auth != ("") {
				SetCond(&conds, extv1alpha1.CondAuthConfigured, tc.auth, extv1alpha1.ReasonReconciling, "")
			}
			if tc.ten != ("") {
				SetCond(&conds, extv1alpha1.CondTenantsReconciled, tc.ten, extv1alpha1.ReasonReconciling, "")
			}
			got, reason, _ := ComputeReady(conds)
			require.Equal(t, tc.wantStatus, got)
			require.Equal(t, tc.wantReason, reason)
		})
	}
}

func Test_RecomputeReadyInPlace_StampsObservedGeneration(t *testing.T) {
	obx := &extv1alpha1.OpenBaoExtension{}
	obx.SetGeneration(7)

	// leaves
	SetCond(&obx.Status.Conditions, extv1alpha1.CondAuthConfigured, metav1.ConditionTrue, extv1alpha1.ReasonSuccess, "")
	SetCond(&obx.Status.Conditions, extv1alpha1.CondTenantsReconciled, metav1.ConditionTrue, extv1alpha1.ReasonSuccess, "")

	RecomputeReadyInPlace(obx)

	ready := FindCond(obx.Status.Conditions, extv1alpha1.CondReady)
	require.NotNil(t, ready)
	require.Equal(t, metav1.ConditionTrue, ready.Status)
	require.Equal(t, int64(7), ready.ObservedGeneration)
}

func Test_RecomputeReadyAndPatch_WithFakeClient(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, extv1alpha1.AddToScheme(scheme))

	obx := &extv1alpha1.OpenBaoExtension{}
	obx.Name = "ex"
	obx.Namespace = "ns"
	obx.SetGeneration(3)
	// leaves: auth true, ten false -> Ready should be False
	SetCond(&obx.Status.Conditions, extv1alpha1.CondAuthConfigured, metav1.ConditionTrue, extv1alpha1.ReasonSuccess, "")
	SetCond(&obx.Status.Conditions, extv1alpha1.CondTenantsReconciled, metav1.ConditionFalse, extv1alpha1.ReasonReconciling, "")

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(obx).
		WithStatusSubresource(obx).
		Build()

	err := RecomputeReadyAndPatch(context.Background(), cl, types.NamespacedName{Namespace: "ns", Name: "ex"})
	require.NoError(t, err)

	var got extv1alpha1.OpenBaoExtension
	require.NoError(t, cl.Get(context.Background(), types.NamespacedName{Namespace: "ns", Name: "ex"}, &got))
	ready := FindCond(got.Status.Conditions, extv1alpha1.CondReady)
	require.NotNil(t, ready)
	require.Equal(t, metav1.ConditionFalse, ready.Status)
	require.Equal(t, int64(3), ready.ObservedGeneration)
}
