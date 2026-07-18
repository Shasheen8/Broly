package iac

import "strings"

func remediation(checkID, guidelineURL string) string {
	id := strings.TrimSpace(checkID)
	guidelineURL = strings.TrimSpace(guidelineURL)
	suggestion := ""

	switch {
	case strings.HasPrefix(id, "CKV_AWS_"):
		suggestion = awsRemediation(id)
	case strings.HasPrefix(id, "CKV_K8S_"):
		suggestion = k8sRemediation(id)
	case strings.HasPrefix(id, "CKV_AZURE_"):
		suggestion = azureRemediation(id)
	case strings.HasPrefix(id, "CKV_GCP_"):
		suggestion = gcpRemediation(id)
	}

	if suggestion == "" {
		suggestion = "Review this infrastructure finding and apply the remediation described in the Checkov documentation."
	}
	if guidelineURL != "" {
		suggestion += " Guide: " + guidelineURL
	}
	return suggestion
}

func awsRemediation(id string) string {
	switch id {
	case "CKV_AWS_18":
		return "Ensure the S3 bucket has access logging enabled. Add a `logging` block with `target_bucket` and `target_prefix`."
	case "CKV_AWS_19":
		return "Ensure the S3 bucket encryption is enabled. Add a `server_side_encryption_configuration` block."
	case "CKV_AWS_20":
		return "Ensure the S3 bucket ACL does not allow public access. Set `acl` to `private` or remove public ACLs."
	case "CKV_AWS_21":
		return "Ensure the S3 bucket versioning is enabled. Set `versioning { enabled = true }`."
	case "CKV_AWS_52":
		return "Ensure S3 bucket has MFA delete enabled. Add `mfa_delete` to the bucket configuration."
	case "CKV_AWS_53":
		return "Ensure S3 bucket has public-read-only ACL disabled. Set `acl` to `private`."
	case "CKV_AWS_145":
		return "Ensure S3 bucket is encrypted with KMS. Use `sse_algorithm = \"aws:kms\"` with a `kms_master_key_id`."
	case "CKV_AWS_338":
		return "Ensure S3 bucket has a bucket policy that enforces TLS. Add a `resource` policy with `aws:SecureTransport` condition."
	case "CKV_AWS_24":
		return "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22. Restrict the CIDR block to a trusted range."
	case "CKV_AWS_23":
		return "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389. Restrict the CIDR block to a trusted range."
	case "CKV_AWS_260":
		return "Ensure no security groups allow ingress from 0.0.0.0/0 to port 80. Restrict the CIDR block or use an ALB with HTTPS."
	case "CKV_AWS_272":
		return "Ensure no security groups allow ingress from 0.0.0.0/0 to port 443. Restrict the CIDR block to a trusted range."
	case "CKV_AWS_40":
		return "Ensure IAM policies do not allow `Resource: \"*\" with `Action: \"*\"`. Scope policies to specific resources and actions."
	case "CKV_AWS_41":
		return "Ensure IAM policies do not grant full `\"*\"` administrative privileges. Apply least-privilege permissions."
	case "CKV_AWS_107":
		return "Ensure IAM policies do not allow `iam:PassRole` with `Resource: \"*\"`. Scope to specific role ARNs."
	case "CKV_AWS_109":
		return "Ensure IAM policies do not allow `Resource: \"*\" with `Action: \"*\"` or `Resource: \"*\". Scope to specific resources."
	case "CKV_AWS_135":
		return "Ensure RDS instances have encryption enabled. Set `storage_encrypted = true`."
	case "CKV_AWS_136":
		return "Ensure RDS instances have backup retention enabled. Set `backup_retention_period` to at least 1."
	case "CKV_AWS_140":
		return "Ensure RDS instances are not publicly accessible. Set `publicly_accessible = false`."
	case "CKV_AWS_163":
		return "Ensure EKS cluster has encryption config set for secrets. Add `encryption_config` with `resources = [\"secrets\"]`."
	case "CKV_AWS_158":
		return "Ensure KMS keys have rotation enabled. Set `enable_key_rotation = true`."
	case "CKV_AWS_287":
		return "Ensure no IAM users have inline policies. Use managed policies or attach policies via `aws_iam_role` instead."
	case "CKV_AWS_298":
		return "Ensure no EKS cluster has public API endpoint. Set `endpoint_public_access = false` or restrict CIDRs."
	default:
		return "Review this AWS infrastructure finding and apply the remediation described in the Checkov documentation."
	}
}

func k8sRemediation(id string) string {
	switch id {
	case "CKV_K8S_10":
		return "Ensure the container does not run as root. Set `securityContext.runAsNonRoot: true`."
	case "CKV_K8S_11":
		return "Ensure the CPU limits are set. Add `resources.limits.cpu` to the container spec."
	case "CKV_K8S_12":
		return "Ensure the memory limits are set. Add `resources.limits.memory` to the container spec."
	case "CKV_K8S_13":
		return "Ensure the CPU requests are set. Add `resources.requests.cpu` to the container spec."
	case "CKV_K8S_14":
		return "Ensure the memory requests are set. Add `resources.requests.memory` to the container spec."
	case "CKV_K8S_15":
		return "Ensure the container image tag is not `latest`. Pin to a specific version or digest."
	case "CKV_K8S_16":
		return "Ensure the container does not have `privileged: true`. Remove `privileged` or set to `false`."
	case "CKV_K8S_17":
		return "Ensure the container does not mount the Docker socket. Remove `/var/run/docker.sock` from volume mounts."
	case "CKV_K8S_18":
		return "Ensure the container does not use `hostNetwork: true`. Remove `hostNetwork` or set to `false`."
	case "CKV_K8S_19":
		return "Ensure the container does not use `hostPID: true`. Remove `hostPID` or set to `false`."
	case "CKV_K8S_20":
		return "Ensure the container does not use `hostIPC: true`. Remove `hostIPC` or set to `false`."
	case "CKV_K8S_21":
		return "Ensure the default namespace is not used. Specify a non-default namespace in `metadata.namespace`."
	case "CKV_K8S_22":
		return "Ensure the container does not use `allowPrivilegeEscalation: true`. Set `allowPrivilegeEscalation: false`."
	case "CKV_K8S_23":
		return "Ensure the container does not use `readOnlyRootFilesystem: false`. Set `readOnlyRootFilesystem: true`."
	case "CKV_K8S_25":
		return "Ensure the seccomp profile is set to `RuntimeDefault` or `Localhost`. Add `securityContext.seccompProfile`."
	case "CKV_K8S_26":
		return "Ensure the container does not have capabilities that allow it to escalate privileges. Drop `ALL` and add only needed capabilities."
	case "CKV_K8S_27":
		return "Ensure the container does not mount sensitive host directories. Remove host path mounts like `/etc`, `/root`, `/var/run`."
	case "CKV_K8S_28":
		return "Ensure the container does not use `runAsUser: 0`. Set `securityContext.runAsUser` to a non-zero UID."
	case "CKV_K8S_29":
		return "Ensure the seccomp profile is not `Unconfined`. Set to `RuntimeDefault` or `Localhost`."
	case "CKV_K8S_30":
		return "Ensure the container has a `readinessProbe` defined for liveness checks."
	case "CKV_K8S_31":
		return "Ensure the container has a `livenessProbe` defined for health checks."
	case "CKV_K8S_38":
		return "Ensure the container does not use `automountServiceAccountToken: true`. Set to `false` when not needed."
	case "CKV_K8S_40":
		return "Ensure the container does not mount host PID. Remove `hostPID: true` from the pod spec."
	case "CKV_K8S_41":
		return "Ensure the service does not use `type: NodePort`. Use `ClusterIP` or an `Ingress` for external access."
	case "CKV_K8S_43":
		return "Ensure the container does not use `capabilities: NET_RAW`. Drop `NET_RAW` from the container capabilities."
	default:
		return "Review this Kubernetes manifest finding and apply the remediation described in the Checkov documentation."
	}
}

func azureRemediation(id string) string {
	switch id {
	case "CKV_AZURE_1":
		return "Ensure Azure instance has no public IP assignment. Use a private IP or internal load balancer."
	case "CKV_AZURE_3":
		return "Ensure Azure storage account has secure transfer required enabled. Set `enable_https_traffic_only = true`."
	case "CKV_AZURE_17":
		return "Ensure Azure Key Vault allows only required access policies. Scope to specific key, secret, and certificate permissions."
	default:
		return "Review this Azure infrastructure finding and apply the remediation described in the Checkov documentation."
	}
}

func gcpRemediation(_ string) string {
	return "Review this GCP infrastructure finding and apply the remediation described in the Checkov documentation."
}
