## Finding

### Title
Webhook signature is verified against the organization named in an unvalidated payload field, decoupling "organization authenticated" from "repository written" - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC signature against by reading an attacker-controlled field out of the still-unverified JSON body. The event handlers that are subsequently invoked act on a completely different field of that same unverified body (`repository.full_name`) to decide which `Stack` to mutate. Nothing in the request enforces that these two fields refer to the same organization, so the binding `organization_that_authenticated == repository_that_is_written` is not actually enforced by the code.

### Finding Description
`repository_owner` is computed straight from the raw, not-yet-verified JSON body: [1](#0-0) 

This value is used to pick the `GithubApp` instance (and therefore the `webhook_secret`) used to verify `X-Hub-Signature`: [2](#0-1) 

`GithubApp#verify_webhook_signature` trivially returns `true` when no `webhook_secret` is configured for that organization: [3](#0-2) 

Once `verify_signature` passes (either because a valid signature for the org named in `repository_owner` was supplied, or because that org has no `webhook_secret` configured at all - a state explicitly shown as the default in the sample secrets file), the controller dispatches the *entire, unmodified* `params` hash to the registered handlers: [4](#0-3) 

Handlers (e.g. the `push` handler that enqueues `GithubSyncJob`, per the webhooks test suite) locate the target `Stack` using `repository.full_name`/`repository.owner.login` taken from that same payload, independent of the `repository_owner` value that governed signature verification. There is no code path that checks `repository.full_name`'s owner segment matches the organization whose secret was used to authenticate the request. Consequently, if *any* organization configured on the Shipit instance has a blank `webhook_secret` (the value defaults to `nil`, as shown in `config/secrets.development.shopify.yml`), an attacker can send a completely unsigned webhook that:
1. Sets `repository.owner.login`/`organization.login` to that unsecured organization, so `verify_signature` passes unconditionally.
2. Sets `repository.full_name` to any other stack's repository (e.g. `"victim-org/victim-repo"`) that is actually configured in Shipit under a *different*, properly-secured organization.

The handler dispatch never re-derives or re-checks the organization from the field it actually acts on, so the request is processed as if it legitimately originated from `victim-org`.

### Impact Explanation
This lets an unauthenticated network attacker forge GitHub webhook events (push, status, commit_status, membership, etc.) for any stack tracked by the Shipit instance, as long as one onboarded organization lacks a webhook secret. Depending on which handler is invoked this enables unauthenticated writes into `Stack`/`Commit`/`Status` state (e.g. injecting fabricated commit-status records used to gate CI checks, or triggering `GithubSyncJob`) for repositories the attacker has no legitimate relationship to, which can influence continuous-delivery decisions (`Stack#trigger_continuous_delivery`) and effectively cause unauthorized deploy triggering for a repository the attacker never authenticated against. This matches the "unauthorized deploy" / "unauthenticated ... write" class of High/Critical impact defined in scope.

### Likelihood Explanation
Exploitation requires no credentials, no `ApiClient` token, no `webhook_secret`, and no repository write access — only that the operator has onboarded more than one GitHub organization to the same Shipit deployment and at least one has no `webhook_secret` set (the documented/sample default). This is a realistic and commonly-seen misconfiguration for the "test"/no-secret organizations, and the vulnerable code path (`verify_signature` → unconditional `params` dispatch) is exercised on every webhook request, requiring no special conditions beyond that configuration state.

### Recommendation
Cross-validate the organization used for signature verification against the organization actually referenced by the fields each handler acts on (e.g., require that `repository.full_name`'s owner segment match the `repository_owner` used to select the signing secret), and reject (or at minimum warn loudly and refuse to process) webhooks for organizations with a blank `webhook_secret` in any environment where multiple organizations are configured. Consider requiring `webhook_secret` to be present for all configured organizations, and fail closed rather than fail open when it's absent.

### Proof of Concept
Given a Shipit deployment configured with two organizations, e.g.:
```yaml
github:
  test-org:
    app_id: ...
    webhook_secret: # blank / nil
  victim-org:
    app_id: ...
    webhook_secret: "s3cr3t"
```
and a stack for `victim-org/victim-repo` tracked by Shipit, an attacker sends (no `X-Hub-Signature` needed, since `test-org` has no secret):

```
POST /webhooks
X-Github-Event: push
Content-Type: application/json

{
  "repository": {
    "owner": { "login": "test-org" },
    "full_name": "victim-org/victim-repo"
  },
  "after": "<attacker-chosen-sha>",
  ...
}
```

`verify_signature` resolves `repository_owner` to `"test-org"`, whose `webhook_secret` is blank, so `verify_webhook_signature` short-circuits to `true` regardless of the (absent) signature header [5](#0-4) . The controller then calls the `push` handler with the full `params`, which resolves the target stack from `repository.full_name` = `"victim-org/victim-repo"`, processing the forged event as if it had been properly signed by `victim-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
