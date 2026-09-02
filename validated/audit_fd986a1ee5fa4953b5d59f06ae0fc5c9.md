### Title
Webhook signature check silently passes when no `webhook_secret` is configured, decoupling the authenticated organization from the repository the handler actually writes to - ([File: app/controllers/shipit/webhooks_controller.rb])

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/organization to verify against using `repository_owner`, taken from the request body itself (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), and delegates the actual check to `GithubApp#verify_webhook_signature`: [1](#0-0) 

That method contains an early-exit: `return true unless webhook_secret`, meaning any organization configured without a `webhook_secret` (explicitly documented as "optional" in `docs/setup.md` and shown as `# nil` in `config/secrets.development.example.yml`) accepts **any** payload with **any** (or no) `X-Hub-Signature` header: [2](#0-1) 

Once the request passes this check, the actual record that gets mutated is determined by a *different, unauthenticated* field inside the same JSON body: `Handler#repository_name` reads `payload.dig('repository', 'full_name')`, which is used to look up `Repository.from_github_repo_name` and the `stacks` that handlers operate on: [3](#0-2) 

Nothing re-validates that `repository.full_name`'s owner matches the `repository_owner`/organization whose (non-)secret was used to "verify" the request. This breaks the equality binding: `organization whose webhook secret authenticated the request` ≠ `repository.full_name that PushHandler/StatusHandler/CheckSuiteHandler/MembershipHandler actually act on`. Deployments with multiple GitHub Apps configured per organization (`test/dummy/config/secrets_double_github_app.yml` shows this is a supported topology) can have one org secured and another left with no secret; a request "authenticated" against the unsecured org can still carry a `repository.full_name`/`organization.login` pointing at the secured org's data.

### Impact Explanation
An unprivileged attacker with no Shipit session, no `ApiClient` token, and no `webhook_secret` can POST directly to the public `/webhooks` endpoint (no `before_action` requires authentication there, only `verify_signature`) and, for any organization configured without a webhook secret, have arbitrary payloads processed as genuine GitHub events:
- `StatusHandler` lets the attacker forge a "success" CI status for an arbitrary existing commit SHA (`Commit.where(sha: params.sha)`), which can satisfy `ci.require` gating and unblock/trigger continuous deployment of a commit that never actually passed CI — an unauthorized deploy.
- `PushHandler` lets the attacker force `stack.sync_github(expected_head_sha: ...)` for arbitrary stacks/branches.
- `MembershipHandler` lets the attacker create/modify `Team`/`Membership` records tied to `Shipit.github_teams`, which directly feeds `User#authorized?` — a path toward escalation into authorization.

This satisfies the Critical/High impact bar (unauthorized deploy, escalation into `Shipit.github_teams` authorization) without any credential.

### Likelihood Explanation
Likelihood is dependent on deployment configuration: it requires at least one configured GitHub App/organization with no `webhook_secret` set, which the project's own setup docs and example secrets file present as a normal, supported ("optional") configuration, and the codebase explicitly supports multiple organizations with independent secrets. Any installation that leaves the webhook secret blank on any configured org (single- or multi-org) is directly exploitable with no attacker credentials.

### Recommendation
Make `webhook_secret` presence mandatory for any configured GitHub App/organization used in production, and fail closed (`head(422)`) when a secret is missing rather than returning `true`. Additionally, after signature verification succeeds, cross-check that `repository.owner.login`/`organization.login` used to select the signing app actually matches the `repository.full_name` owner that handlers act upon, rejecting mismatches.

### Proof of Concept
1. Configure two GitHub Apps in `secrets.yml`, e.g. `OrgA` (attacker-controlled, no `webhook_secret`) and `OrgB` (victim, has a repo/stack tracked by Shipit).
2. POST to `/webhooks` with header `X-Github-Event: status` and no valid `X-Hub-Signature` (or any garbage value), and body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
3. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA").verify_webhook_signature(...)`, which returns `true` immediately because `OrgA` has no `webhook_secret`.
4. `StatusHandler` then processes the event against `Commit.where(sha: params.sha)` for the victim's commit, writing a forged "success" status that was never produced by GitHub CI, potentially unblocking continuous deployment of that commit.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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
