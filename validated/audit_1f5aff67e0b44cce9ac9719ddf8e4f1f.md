### Title
Attacker-controlled `repository.owner.login` selects the GitHub App/secret used for webhook signature verification, decoupling the authenticated organization from the repository actually acted upon - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which `GitHubApp` (and therefore which `webhook_secret`) to validate the incoming HMAC signature against, based on `repository_owner`, a field read straight out of the **unverified** JSON body. Every downstream `Handler` then resolves the target `Repository`/`Stack` using a *different* field from the same unverified body: `payload.dig('repository', 'full_name')`. Because Shipit explicitly supports multiple GitHub Apps/organizations, each with its own independently-configured (and optionally blank) `webhook_secret`, the organization whose credentials authenticate the request is not bound to the repository the request is permitted to mutate.

### Finding Description
The controller resolves the signing organization purely from payload content, before any signature has been checked: [1](#0-0) [2](#0-1) 

`verify_webhook_signature` then trivially returns `true` when that organization's `webhook_secret` is blank/unset: [3](#0-2) 

`webhook_secret` is a documented, optional per-organization setting (`webhook_secret: # nil` appears in the example configs and setup docs), and Shipit explicitly supports configuring several organizations, each with independent App credentials: [4](#0-3) [5](#0-4) 

Once the request clears `verify_signature`, every `Handler` resolves the actual object being mutated from `repository.full_name` in the same, still only-optionally-authenticated payload: [6](#0-5) 

This is the same class of bug as the Curve `lp_token()`/`token()` mismatch: a security-critical decision (which "version"/entity governs behavior) is derived from one field, while the action actually taken operates on a different, related-but-distinct field, and the two are never checked for consistency. Here, the field used to pick the trust anchor (`repository.owner.login`) is never bound to the field used to select the resource acted upon (`repository.full_name`). If an operator has configured more than one GitHub organization (a documented use case) and any one of them has no `webhook_secret` configured, an unauthenticated attacker can:
1. Craft any GitHub webhook payload (`push`, `status`, `check_suite`, `membership`, `pull_request`, etc.).
2. Set `repository.owner.login` (or `organization.login`) to the name of the organization lacking a `webhook_secret`, causing `verify_webhook_signature` to short-circuit to `true`.
3. Set `repository.full_name` (used by `Handler#repository_name`/`#stacks`) to any other repository/stack hosted on the very same Shipit instance, including ones belonging to a *different*, properly-secured organization.
4. The handler then acts on the attacker-chosen repository/stack with full trust, e.g. `PushHandler` triggers `stack.sync_github`, `MembershipHandler` adds/removes users from `Team`s, `StatusHandler`/`CheckSuiteHandler` fabricate commit statuses/check-runs that feed merge-queue and deploy-eligibility logic. [7](#0-6) [8](#0-7) 

### Impact Explanation
This breaks the binding "organization that authenticated" = "repository that is written." The authentication check verifies nothing about the repository actually being mutated — it only proves the requester knows a secret (or that no secret exists) for a *self-declared* organization name in the same unauthenticated payload. This allows cross-repository/cross-organization writes: fabricated commit statuses (`StatusHandler`) can influence deploy/merge decisions, `MembershipHandler` can add arbitrary GitHub logins to a `Team` (affecting `User#authorized?`, i.e. authentication/authorization into the app itself), and `PushHandler`/`CheckSuiteHandler` can force syncs on stacks the attacker does not own. Per the impact rubric, unauthorized cross-repository writes and escalation into `Shipit.github_teams` authorization are explicitly Critical/High-severity outcomes.

### Likelihood Explanation
The precondition (multiple GitHub organizations configured, at least one without a `webhook_secret`) is an explicitly documented, supported configuration rather than a misconfiguration outside the engine's design — the shipped example config (`config/secrets.development.example.yml`) and `docs/setup.md`'s multi-org section both show `webhook_secret` as optional/nilable per organization. Any operator who onboards a second, lower-trust or convenience organization without setting its webhook secret exposes every other organization's stacks on the same instance to spoofed events, with no attacker credentials required beyond crafting an HTTP POST.

### Recommendation
Bind signature verification to the same repository the handler will act on: derive the organization to verify against from a value tied to the resource actually mutated (e.g., look up the `Repository`/`Stack` by `full_name` first, and verify the signature using the `webhook_secret` of the organization actually owning that persisted `Repository`, not an attacker-supplied `repository.owner.login`/`organization.login`). Additionally, disallow completely unauthenticated processing when any configured app has no `webhook_secret`: require a `webhook_secret` for all configured organizations, or refuse to select an app for verification based on unverified payload content at all.

### Proof of Concept
Given a Shipit instance configured with two organizations as in `test/dummy/config/secrets_double_github_app.yml` (`OrgOne` with a real `webhook_secret`, `OrgTwo` with `webhook_secret:` blank), and a `Repository`/`Stack` that syncs `OrgOne/private-repo`:

1. POST to `/webhooks` with header `X-Github-Event: push`.
2. Body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "OrgTwo" },
    "full_name": "OrgOne/private-repo"
  }
}
```
3. `verify_signature` calls `Shipit.github(organization: 'OrgTwo')`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the (absent/garbage) `X-Hub-Signature` header (`lib/shipit/github_app.rb:76-83`).
4. `PushHandler#process` resolves `stacks` via `payload.dig('repository', 'full_name')` = `"OrgOne/private-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) and enqueues `stack.sync_github(expected_head_sha: ...)` for that stack — an organization the attacker never authenticated against.

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

**File:** config/secrets.development.example.yml (L18-38)
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
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
```ruby
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end
```
