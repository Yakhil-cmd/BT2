### Title
Webhook signature verification is keyed to an attacker-controlled `repository.owner.login`/`organization.login` field while the write target is selected by a different, unbound payload field, allowing forged writes from any GitHub organization whose app config has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to authenticate a webhook against by reading `repository.owner.login` (falling back to `organization.login`) straight out of the still-unverified JSON body, before HMAC validation runs. `GitHubApp#verify_webhook_signature` unconditionally returns `true` when the resolved app has no configured `webhook_secret`. Every event handler, however, decides what to write using a *different* field from the same body: `PushHandler`/base `Handler#repository_name` uses `repository.full_name`, `StatusHandler` uses a bare commit `sha` with no repository scoping at all, and `MembershipHandler` mutates the global `Team`/`Membership` tables keyed on `team.id`/`organization.login`. None of these write-path fields are cross-checked against the identity that was actually authenticated.

### Finding Description
The authentication binding is:
`authenticated_org = params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  is used to look up the `GitHubApp` instance whose secret verifies the signature [2](#0-1) .

`GitHubApp#verify_webhook_signature` returns `true` with no cryptographic check whenever that app's `webhook_secret` is blank: `return true unless webhook_secret` [3](#0-2) . The setup docs explicitly document `webhook_secret` as optional/copy-if-set, i.e. a supported, non-degraded configuration state [4](#0-3) .

The write path is bound to unrelated fields from the same, now-"verified" payload:
- `Handler#repository_name` reads `payload.dig('repository', 'full_name')` to resolve the target `Repository`/`Stack`, independent of `repository.owner.login` [5](#0-4) .
- `PushHandler#process` uses that repository lookup to run `stack.sync_github(...)` for every matching, non-archived stack [6](#0-5) .
- `StatusHandler#process` looks up commits purely by `sha` across the whole install (`Commit.where(sha: params.sha)`) with no repository/owner filter at all, and writes a status [7](#0-6) .
- `MembershipHandler#process` creates/updates global `Team`/`Membership` records keyed on `team.id` and `organization.login`, with no tie back to the `repository_owner` used for signature selection [8](#0-7) .

The equality that should hold is:
`organization authenticated by verify_signature == organization whose data is written by the handler`

Before the attacker's request: this equality holds implicitly only because in the intended flow the same organization's payload is both the signer and the subject. After the attacker's request: an attacker who has no secret for the target organization can set `repository.owner.login` (or `organization.login`) to any configured org that has a blank `webhook_secret`, causing `verify_webhook_signature` to short-circuit to `true` for the *entire* raw body — while placing an arbitrary `repository.full_name`, `sha`, or `team`/`organization` block belonging to a *different, secret-protected* organization/repository inside that same body. Signature verification never re-derives or checks that the "owner" used for authentication matches the "full_name"/"sha"/"organization" used for the write, because both simply came from a single unverified JSON blob that was accepted wholesale once any zero-secret app's `verify_webhook_signature` returned `true`.

### Impact Explanation
This lets an unprivileged external attacker (no `webhook_secret`, no `ApiClient` token, no repository write access) forge webhook deliveries directly to the engine's `/webhooks` endpoint that: (a) trigger `GithubSyncJob`/deploy-pipeline-relevant syncs for stacks belonging to a different, secret-protected organization via `PushHandler`, (b) write arbitrary commit statuses onto any commit in the system via `StatusHandler` (no owner scoping at all), and (c) create/delete `Team` membership records across the whole installation via `MembershipHandler`, which is used elsewhere to gate `Shipit.github_teams` authorization. This is a direct escalation into the "authorization/membership" and "unauthorized write" categories the analog rules classify as High, achieved purely by exploiting the mismatch between the field used to select the verifying secret and the fields used to decide what gets written.

### Likelihood Explanation
Likelihood is high in any multi-organization Shipit deployment where at least one configured GitHub App entry omits `webhook_secret` (an explicitly documented, supported configuration) — the attacker needs no credentials at all, only knowledge that such an org exists and its login, both of which are typically public (GitHub org names are public).

### Recommendation
`verify_signature` must select the verifying `GitHubApp` from a value that is itself bound to the request's actual authenticated identity, and handlers must re-validate that all subject fields used for writes (`repository.full_name`, commit `sha`'s owning repository, `organization.login`/`team.organization`) belong to the same organization that was cryptographically authenticated — not merely echo values found elsewhere in the same JSON body. Additionally, `verify_webhook_signature`'s `return true unless webhook_secret` fallback should not silently authenticate arbitrary payloads; a missing secret should either reject the webhook or be scoped so it can never vouch for data belonging to a different, secret-protected organization.

### Proof of Concept
1. Deployment configures two GitHub Apps: `OrgA` (no `webhook_secret` set) and `OrgB` (secret configured, stacks/commits/teams belong to OrgB).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>"
}
```
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgA")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the `X-Hub-Signature` header value [9](#0-8) .
4. `PushHandler#process` resolves `Repository.from_github_repo_name("OrgB/target-repo")` and calls `sync_github` on OrgB's stacks, even though OrgB's secret was never checked [5](#0-4) [6](#0-5) .
5. Analogously, a forged `membership` event with `organization.login: "OrgA"` but arbitrary `team`/`member` data mutates global `Team`/`Membership` state used for `Shipit.github_teams` authorization [8](#0-7) .

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

**File:** docs/setup.md (L117-119)
```markdown
**`github.bot_login`** The login of the App [bot] user. Every GitHub App have an associated `[bot]` user which acts as the author of the App actions through the API, for example when an App merges a Pull Request. It should be the App "slug" with the suffix `[bot]`. For example if your app settings URL is `https://github.com/organizations/ACME/settings/apps/acme-shipit/installations`, the bot user should be `acme-shipit[bot]`. If you are unsure, you can leave it empty.

**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
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

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```
