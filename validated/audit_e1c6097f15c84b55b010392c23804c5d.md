### Title
Webhook signature verification is scoped to an attacker-chosen organization while handlers act on an unrelated repository field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC signature with based on an unauthenticated field taken straight from the request body, while the handlers that actually mutate state (enqueue syncs, deploys-related jobs, check-run refreshes, memberships) key off a *different* field (`repository.full_name`) that is never tied back to the organization whose secret was used to "verify" the request. Combined with `GithubApp#verify_webhook_signature` returning `true` unconditionally when an organization has no `webhook_secret` configured, this breaks the binding "organization authenticated == repository that is written."

### Finding Description
`verify_signature` derives the org used for signature verification purely from the untrusted payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the `GithubApp` config for whatever organization the attacker put in `repository.owner.login` (or `organization.login`), then calls `verify_webhook_signature`: [3](#0-2) 

Note line 77: `return true unless webhook_secret` — if the selected organization has no `webhook_secret` configured (a state explicitly supported/documented, e.g. `webhook_secret: # nil` in `test/dummy/config/secrets_double_github_app.yml` and `config/secrets.development.shopify.yml`), verification trivially passes for *any* body, regardless of the actual signature header.

After this check "passes," `WebhooksController#create` dispatches the entire raw payload to handlers: [4](#0-3) 

But the handlers do not use `repository.owner.login` (the field that gated signature verification) — they use `repository.full_name` to resolve the target `Repository`/`Stack`: [5](#0-4) 

For example, `PushHandler` uses this to find non-archived stacks matching an attacker-supplied branch and immediately triggers `stack.sync_github(expected_head_sha: params.after)`: [6](#0-5) 

`CheckSuiteHandler` similarly locates stacks/commits by `repository.full_name` and schedules check-run refreshes based on attacker-controlled `head_sha`/`head_branch`: [7](#0-6) 

`StatusHandler` writes a commit status keyed only by `sha`, with no repository/organization scoping at all: [8](#0-7) 

Because a Shipit deployment can be configured with multiple GitHub organizations (as shown by the multi-org secrets fixture and `Shipit.github(organization:)` lookup pattern), an attacker only needs one organization in the install to have no `webhook_secret` set (or to know/guess any organization name Shipit will accept without raising `GithubOrganizationUnknown`) to have `verify_signature` short-circuit to `true` for a forged payload whose `repository.full_name` names a completely different, protected repository/stack belonging to a different organization that *does* have a webhook secret. The equality that should hold — "the organization whose signature was verified" == "the repository/organization the handler acts on" — does not hold anywhere in this code path.

### Impact Explanation
This allows an unauthenticated attacker to forge GitHub webhook events (`push`, `check_suite`, `status`, `membership`, `pull_request`, etc.) for a repository/stack they do not control, as long as any organization configured on the Shipit instance lacks a `webhook_secret`. Consequences: forcing `GithubSyncJob`/`stack.sync_github` execution and check-run refresh scheduling against a target stack under attacker influence over `after`/`head_sha`, forging commit statuses that Shipit relies on for deploy gating, and creating/mutating `Team`/`Membership` records — all without any credential. Depending on how sync/status data feeds into deploy-readiness gating (e.g., statuses used to allow/block shipping), this can escalate into an unauthorized deploy trigger. This matches Impact-High ("unauthenticated read/…forced session"/authorization escalation class) at minimum, potentially Critical if sync/status manipulation can be chained into triggering a deploy.

### Likelihood Explanation
Likelihood is Low-to-Medium: it requires an operator to run Shipit with at least one multi-org configuration where one organization is left without a `webhook_secret` (a state the codebase's own test/dummy fixtures and doc templates explicitly show as a supported/expected configuration), or requires the attacker to correctly guess/know an org name that maps to a `GithubApp` with a blank secret. Single-organization deployments with a secret configured are not exploitable via this path.

### Recommendation
Bind organization-derived verification to the same field the handler actually consumes: verify the signature using the organization/app config corresponding to `repository.full_name`'s owner (not a separately-dug field), and reject payloads whose `repository.owner.login`/`organization.login` do not match the owner encoded in `repository.full_name`. Additionally, do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank for a *configured* organization in a multi-org deployment — either require a secret for every configured org or fail closed (reject) rather than fail open when a secret is absent while other orgs in the same instance do have secrets.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `OrgA` (has `webhook_secret: s3cr3t`) hosting the real target stack `OrgA/critical-repo`, and `OrgB` (has `webhook_secret:` blank/nil), as supported per `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker sends `POST /webhooks` with header `X-Github-Event: push`, no valid `X-Hub-Signature` (or any garbage value), and body:
```json
{
  "ref": "refs/heads/main",
  "after": "attacker_controlled_sha",
  "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/critical-repo" }
}
```
3. `repository_owner` resolves to `"OrgB"`; `Shipit.github(organization: "OrgB")` returns the `GithubApp` with a blank `webhook_secret`; `verify_webhook_signature` returns `true` at line 77 regardless of the (invalid) signature header — request passes `verify_signature`.
4. `PushHandler#process` is invoked with the full payload, resolves `Repository.from_github_repo_name("OrgA/critical-repo")` via `repository_name` (`repository.full_name`), and calls `stack.sync_github(expected_head_sha: "attacker_controlled_sha")` on the real, protected stack under `OrgA` — despite the request never being authenticated for `OrgA`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
