### Title
Webhook signature verification is keyed on `repository.owner.login`/`organization.login` while the write action is keyed on `repository.full_name` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and thus which `webhook_secret`) to validate the HMAC against using one JSON field of the *unverified* payload, while every webhook handler resolves the actual `Stack`/`Repository` to mutate using a *different* JSON field of the same payload. Nothing binds these two fields together, so verification success for organization "A" does not guarantee that the write action targets a repository belonging to "A".

### Finding Description
`repository_owner` extracts the organization used to pick the verifying `GithubApp`: [1](#0-0) 

```ruby
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

This value drives `Shipit.github(organization: repository_owner)` and the HMAC check: [2](#0-1) 

However, every webhook handler resolves the repository to write to via a **different** field of the same body, `repository.full_name`, not `repository.owner.login`: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler` then acts on whatever stacks match that `full_name`: [4](#0-3) 

`verify_webhook_signature` unconditionally passes when the selected app has no `webhook_secret` configured: [5](#0-4) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

This is exactly analogous to the reNFT `disableModule` bug: the value that is *checked* (`repository.owner.login`, used to pick the org whose secret authenticates the whole request) is not the value that is *acted upon* (`repository.full_name`, used to resolve the target `Repository`/`Stack`). The two fields are never cross-validated against each other.

### Impact Explanation
In a Shipit deployment configured with more than one GitHub App/organization (a documented, supported configuration — see `docs/setup.md`, "Using Multiple Github Applications"), if any single configured organization has no `webhook_secret` set (`webhook_secret: nil`, also a documented, supported value), that organization becomes a skeleton key for every other configured, properly-secured organization:

- An unauthenticated caller (no session, no API token, no knowledge of any secret) POSTs to `/webhooks` with header `X-Github-Event: push` and a body where `repository.owner.login` is the unsecured org (so `verify_webhook_signature` returns `true` unconditionally) but `repository.full_name` names a repository belonging to the fully-secured organization.
- `verify_signature` passes (equality broken: "organization that authenticated" ≠ "repository that is written").
- `PushHandler#process` resolves the *real* target stack via `full_name` and calls `stack.sync_github(expected_head_sha: params.after)` with an attacker-chosen SHA, which can force a resync and — for stacks with `continuous_deployment` enabled or `ignore_ci` set — trigger an unauthorized deploy of an attacker-influenced revision, without ever knowing the secured organization's real `webhook_secret`.

This meets the High/Critical bar of "an unauthorized deploy" via a broken authentication↔repository binding.

### Likelihood Explanation
Requires only that the operator has configured at least two GitHub organizations (a documented use case) and left one of them without a `webhook_secret` (also a documented, accepted configuration, e.g. for a low-risk/test org). No credentials, sessions, or secrets are needed by the attacker; the endpoint (`/webhooks`) is unauthenticated by design and reachable pre-verification.

### Recommendation
Bind verification and effect to the same authenticated field: after selecting `github_app` via `repository_owner` and validating the signature, re-derive the acted-upon repository strictly from that same verified organization (e.g., require `repository.full_name.split('/').first == repository_owner`, case-insensitively) before dispatching to any handler, or verify the signature using a single, deployment-wide invariant rather than a value taken from the unauthenticated payload. Additionally, consider requiring `webhook_secret` to be present for every configured organization (fail closed) rather than silently accepting unsigned payloads for any org that omits it.

### Proof of Concept
Preconditions: multi-org Shipit config as in `docs/setup.md` (`OrgUnsecured` with `webhook_secret: nil`, `OrgSecured` with a real secret and a stack tracking `OrgSecured/critical-repo`, branch `main`, `continuous_deployment: true`).

```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "OrgUnsecured" },
    "full_name": "OrgSecured/critical-repo"
  }
}
```

- `repository_owner` returns `"OrgUnsecured"` → `Shipit.github(organization: "OrgUnsecured")` has `webhook_secret == nil` → `verify_webhook_signature` returns `true` with no `X-Hub-Signature` header at all.
- `PushHandler#stacks` resolves `Repository.from_github_repo_name("OrgSecured/critical-repo")` → matches the real, secured stack, and `stack.sync_github(expected_head_sha: "deadbeef...")` is invoked, potentially cascading into an unauthorized deploy for a stack the attacker has no legitimate access to.

Note: I could not verify from the index whether `MembershipHandler` (which resolves teams via `organization.login`, the same field used for verification for org-scoped events) has an analogous split for team/membership writes; that handler uses the *same* field for both verification-org-selection and the write target, so it does not exhibit this particular binding break, but the push/pull_request/status family of handlers (which key on `repository.full_name`) all do.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
