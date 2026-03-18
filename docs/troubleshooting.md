# Troubleshooting

This guide helps you resolve common issues encountered while setting up or running the Zelyo Operator.

## Webhooks

### Error: "the server could not find the requested resource"
When applying a `SecurityPolicy`, you may encounter an error like this:
`Error from server (InternalError): error when creating "test-security-policy.yaml": Internal error occurred: failed calling webhook "msecuritypolicy.zelyo.ai": failed to call webhook: the server could not find the requested resource`

#### Root Cause
This typically happens when the path defined in the `MutatingWebhookConfiguration` or `ValidatingWebhookConfiguration` does not match the path the operator is listening on. 

In some versions of the Helm chart, the paths use the domain `zelyo-operator-com`, while the operator uses `zelyo-ai`.

#### Solution (Manual Patch)
Run these commands to align the configuration with the operator:

```bash
# Patch the Mutating Webhook
kubectl patch mutatingwebhookconfiguration zelyo-operator --type='json' \
  -p='[{"op": "replace", "path": "/webhooks/0/clientConfig/service/path", "value": "/mutate-zelyo-ai-v1alpha1-securitypolicy"}]'

# Patch the Validating Webhook
kubectl patch validatingwebhookconfiguration zelyo-operator --type='json' \
  -p='[{"op": "replace", "path": "/webhooks/0/clientConfig/service/path", "value": "/validate-zelyo-ai-v1alpha1-securitypolicy"}]'
```


