// Package v1alpha1 holds VCO-origin primitive CRDs under the
// security.mto.stakater.com/v1alpha1 group. See docs/plans/PLAN-vco-cherrypick-roadmap.md.
//
// +kubebuilder:object:generate=true
// +groupName=security.mto.stakater.com
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	GroupVersion  = schema.GroupVersion{Group: "security.mto.stakater.com", Version: "v1alpha1"}
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	AddToScheme   = SchemeBuilder.AddToScheme
)
