package v1alpha1

// Condition types for OpenBaoExtension.
const (
	CondReady             = "Ready"
	CondAuthConfigured    = "AuthConfigured"
	CondTenantsReconciled = "TenantsReconciled"
)

// Standard reasons used across controllers when setting conditions.
const (
	ReasonSuccess             = "Success"
	ReasonWaitingDependencies = "WaitingForDependencies"
	ReasonReconciling         = "Reconciling"
	ReasonError               = "Error"
)
