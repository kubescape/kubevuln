# Reproducing kubevuln OOM when scanning large images

## Problem

The kubevuln service can be driven to **OOM (Out Of Memory)** when it scans certain large images. The pod is killed by the kernel (`OOMKilled`, exit code 137).

## Trigger

- **Endpoint:** `POST /v1/scanRegistryImage`
- **Payload:** Request to scan the image `gitlab/gitlab-ee` (large image).

Example request:

```bash
curl -X POST http://localhost:8080/v1/scanRegistryImage \
  -H "Content-Type: application/json" \
  -d '{
    "imageTag": "gitlab/gitlab-ee",
    "credentialsList": [
      {
        "username": "",
        "password": ""
      }
    ]
  }'
```

The API returns **200 OK** immediately; the heavy work (pull/scan) runs asynchronously and can cause the pod to exceed its memory limit and be OOMKilled.

## How to reproduce

1. **Lower the kubevuln deployment memory limit** (e.g. to 512Mi) so the OOM is observable:

   ```bash
   kubectl patch deployment kubevuln -n kubescape --type='json' -p='[
     {"op": "replace", "path": "/spec/template/spec/containers/0/resources/limits/memory", "value": "512Mi"},
     {"op": "replace", "path": "/spec/template/spec/containers/0/resources/requests/memory", "value": "512Mi"}
   ]'
   ```

2. **Expose the service** (if testing from the host):

   ```bash
   kubectl port-forward -n kubescape svc/kubevuln 8080:8080
   ```

3. **Send the request** (curl as above to `http://localhost:8080`).

4. **Watch the pod** for OOM: restarts increase and the previous container state shows `Reason: OOMKilled`, `Exit Code: 137`:

   ```bash
   kubectl get pod -n kubescape -l app.kubernetes.io/component=kubevuln
   kubectl describe pod -n kubescape -l app.kubernetes.io/component=kubevuln
   # Check "Last State" / "Restart Count"
   ```

## Observed outcome

- With **512Mi** memory limit: pod is **OOMKilled** within about 1–2 minutes after the POST (restart count goes to 1, last state `OOMKilled`, exit 137).
- With **5000Mi** (default in this setup): OOM was **not** observed in the same time window.

## Context for agents

Use this document as context when working on:

- Reducing memory usage during registry image scans.
- Adding safeguards or limits for large-image scans.
- Setting or recommending resource limits for kubevuln deployments.
