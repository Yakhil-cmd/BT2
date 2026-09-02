### Title
Webhook signature verification binds the wrong field to the mutated resource — organization authenticated ≠ repository/commit written ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb], [File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using `repository_owner` (derived from `payload['repository']['owner']['login']` or `payload['organization']['login']`), but the event handlers that actually mutate state select the target `Repository`/`Stack`/`Commit` using a *different*, unrelated payload field (`repository.full_name`, or in the case of `StatusHandler`, a bare `sha` with no repository scoping at all). The signature therefore never certifies "this organization is authorized to write to this repository/commit" — it only certifies "this payload was signed with the secret belonging to whichever `owner.login` happens to be in the JSON," which the attacker also controls.

### Finding Description
`WebhooksController#verify_signature` does: [1](#0-0) 
using `repository_owner`: [2](#0-1) 

This picks the per-organization `GitHubApp` (and its `webhook_secret`) via `Shipit.github(organization: repository_owner)`, and confirms the HMAC over the raw body was produced with *that org's* secret: [3](#0-2) 

Shipit explicitly supports multiple, independently-configured GitHub Apps/organizations, each with its own `webhook_secret`: [4](#0-3) 

Once the signature check passes, the actual dispatched handler determines *which* record to mutate using a completely different field, `repository.full_name`: [5](#0-4) 

Nothing ties `repository.full_name` back to the `repository_owner` (or `organization.login`) that was used to select the verifying secret. Even worse, `StatusHandler` doesn't call `stacks`/`repository_name` at all — it looks up commits **globally by sha**, with no repository binding whatsoever: [6](#0-5) 

`PushHandler` and `CheckSuiteHandler` do use `repository_name`/`stacks`, but that value is still taken from `repository.full_name` — a field entirely outside the check performed in `verify_signature`: [7](#0-6) [8](#0-7) 

This is the direct analog of the `ERC20Gauges._incrementGaugeWeight` bug: the code checks one property of the "gauge"/organization parameter (not deprecated / has a valid secret) but never checks that the same parameter is the one actually being credited/written (`_gauges.contains(gauge)` / `repository.full_name` belongs to `repository_owner`). The binding that should hold is:

`organization authenticated by verify_signature == organization that owns the repository/commit actually mutated by the handler`

and it does not — the two are read from unrelated JSON paths that an unprivileged attacker fully controls in their own signed request.

### Impact Explanation
An attacker who administers their own GitHub organization/repository and has installed their own GitHub App (or knows their own org's configured `webhook_secret` from `config/secrets.yml`) can produce a validly-signed webhook (`X-Hub-Signature` over the raw body, computed with their own org's secret) while setting:
- `repository.owner.login` (or `organization.login`) = their own org, so `verify_signature`'s secret lookup and HMAC check succeed, and
- `repository.full_name` (`PushHandler`/`CheckSuiteHandler`) or `sha` (`StatusHandler`) = a value belonging to a completely unrelated stack/commit tracked by the same Shipit instance.

For `StatusHandler`, this is most severe: `Commit.where(sha: params.sha)` is unscoped by repository/organization, so a validly-signed status payload from the attacker's own org can write an arbitrary `state`/`description`/`context`/`target_url` (e.g., forging a passing CI status) onto any commit row in the Shipit database that shares that `sha` — including commits belonging to stacks/repositories the attacker has no access to, if that sha is present (e.g., shared history, cherry-picks, or commits merged into multiple tracked repos). Forged green CI statuses can unblock the merge/deploy gating logic (`Commit`/`CommitChecks`), which maps to the "escalation into authorization" / "unauthorized deploy" impact bar.

For `PushHandler`/`CheckSuiteHandler`, the immediate consequence is forcing a resync/check-refresh job against an arbitrary tracked stack using Shipit's own (real) GitHub credentials rather than trusting attacker-supplied commit content — this is a lower-severity confused-deputy trigger and closer to the out-of-scope DoS/rate-limiting category, so it is noted for completeness but the `StatusHandler` path is the concrete, in-scope binding break.

### Likelihood Explanation
Exploitation requires only: (1) the target Shipit instance is configured with more than one GitHub organization/App (documented and supported configuration), and (2) the attacker controls one of those organizations' webhook secrets (their own org, not the victim's) — no Shipit session, API token, or privileged account is required, matching the "unprivileged attacker" bar. The commit-sha collision requirement for the highest-severity `StatusHandler` case narrows real-world likelihood (shared/forked history across tracked repos), but the underlying binding failure (org used for verification ≠ org/commit actually written) is unconditional and present on every request, independent of collision likelihood.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), after signature verification, assert that the organization/owner used to select the verifying secret matches the owner embedded in every field the handler will act on (`repository.full_name`'s owner segment for `PushHandler`/`CheckSuiteHandler`; require and check the commit's actual `Repository`/`Stack` ownership in `StatusHandler` rather than a bare global `sha` lookup). Concretely, `StatusHandler#process` should scope `Commit.where(sha: params.sha)` to commits whose `stack.repository.full_name`/`owner` matches the verified `repository_owner`.

### Proof of Concept
1. Configure Shipit with two orgs, each with its own `webhook_secret` (as shown in `config/secrets.development.example.yml`): `org-a` (attacker-controlled) and `org-b` (victim, tracked in Shipit with commit `abc123`).
2. Attacker computes `X-Hub-Signature: sha1=HMAC(org-a-secret, body)` over a `status` event body where `repository.owner.login = "org-a"` but `sha = "abc123"`, `state = "success"`.
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "org-a")` and successfully verifies the signature against `org-a`'s secret: [1](#0-0) 
4. `StatusHandler#process` updates any `Commit` with `sha == "abc123"`, including the one belonging to the victim's `org-b` stack, with no ownership check: [6](#0-5)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.example.yml (L18-29)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
