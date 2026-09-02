## Analysis: Status/CI webhook data trusts the payload's `repository.full_name` for stack lookup, not the org whose secret verified the request

### Title
Webhook signature verified against `repository.owner.login`'s GitHub App, but stack lookup and commit-status writes trust the unrelated `repository.full_name` field, and `verify_webhook_signature` is a no-op when an org's `webhook_secret` is unset - ([File: app/controllers/shipit/webhooks_controller.rb], [File: lib/shipit/github_app.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
This is the closest analog to the Trader Joe finding's root cause: a value that is *acted upon* by the function is not the same value that was *validated*. In `swapAVAXForExactTokens`, the refund logic operates on `msg.value` (the actually-sent amount) but the guard condition and math never correctly reconcile it with `amountsIn[0]` (the validated/expected amount), so the wrong side of the comparison is used, breaking the expected `sent >= expected` invariant. In Shipit's webhook pipeline, the same class of mismatch occurs between two payload fields that should be bound together but aren't:

- `WebhooksController#verify_signature` selects which GitHub App/secret to check the HMAC against using `repository_owner` = `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) [2](#0-1) .
- `Shipit::Webhooks::Handlers::Handler#stacks` / `#repository_name`, used by `PushHandler`, `CheckSuiteHandler`, and PR handlers, looks up the affected `Stack`/`Repository` using an entirely different field: `payload.dig('repository', 'full_name')` [3](#0-2) .
- `StatusHandler#process` doesn't even scope by repository at all - it matches on `Commit.where(sha: params.sha)` globally and writes a status [4](#0-3) .
- Critically, `GitHubApp#verify_webhook_signature` is a documented no-op when the org has no `webhook_secret` configured: `return true unless webhook_secret` [5](#0-4) , and Shipit's own setup docs explicitly mark `webhook_secret` as **optional** [6](#0-5) , and support multiple GitHub Apps for multiple orgs, each independently configured [7](#0-6) .

### Finding Description
The equality this design is supposed to preserve is:

`organization that authenticated the webhook == organization that owns the repository the handler acts on`

The controller only checks the first half. `repository_owner` is derived from `repository.owner.login` (or `organization.login`), and is used purely to select *which* `GitHubApp` config's secret to HMAC-verify the raw request body against [8](#0-7) . Once `head(422)` isn't triggered, the entire raw JSON body — including a completely independent `repository.full_name` field — is handed to the event handlers unmodified [9](#0-8) .

For any organization configured (per the documented multi-app setup) **without** a `webhook_secret`, `verify_webhook_signature` unconditionally returns `true` for a request whose `repository.owner.login`/`organization.login` names that org [5](#0-4) . Nothing else checks that `repository.owner.login` and `repository.full_name`'s owner segment agree. An attacker who knows (or guesses) that such an org exists in the instance's config can send an arbitrary unsigned POST to `/webhooks` with:
- `X-Github-Event: push` (or `status`, `check_suite`, etc.)
- `repository.owner.login` = the org with no secret (to pass `verify_signature`)
- `repository.full_name` = **any other org/repo** tracked by the instance
- `sha`/`state`/`context` values chosen by the attacker

`WebhooksController#verify_signature` never rejects this, because the org used for verification is fully attacker-chosen and independent from the repository the payload claims to affect. The `PushHandler`/`CheckSuiteHandler` then resolve `stacks` via `Repository.from_github_repo_name(repository_name)` using the attacker-supplied `full_name`, and `StatusHandler` blindly attaches a commit status to any `Commit` row matching the attacker-supplied `sha`, regardless of which org's credentials passed verification [3](#0-2) [4](#0-3) .

### Impact Explanation
This breaks the "organization that authenticated versus the repository that is written" trust binding named in scope. Concretely:
- `StatusHandler` lets the attacker inject a fabricated commit status (e.g. mark a required CI check as `success`) for any commit tracked by Shipit, in any stack, without any authentication tied to that stack's real repository — this can be used to satisfy `required_statuses`/merge-queue CI gating (`app/models/shipit/deploy_spec.rb` `required_statuses`) and push through an unauthorized merge/deploy path.
- `CheckSuiteHandler`/`PushHandler` let the attacker force `sync_github`/`schedule_refresh_check_runs!` against arbitrary stacks whose repositories they don't control.

This matches the High-severity bucket ("escalation into authorization, unauthenticated ... task streams" is not exact, but "unauthorized deploy/merge" via forged status maps to the Critical bucket for "an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Likelihood depends entirely on whether an operator has configured at least one GitHub App entry (in the documented multi-org `github:` block) without a `webhook_secret`. Since the setup docs explicitly present `webhook_secret` as optional and per-org, this is a plausible real-world misconfiguration rather than a theoretical one, and no privileged credentials (session, API token, GitHub App private key) are required to exploit it once such a gap exists — only knowledge/guessing of an org name in the instance's config. I could not verify from the indexed code whether there is any additional cross-check elsewhere (e.g., in `Repository.from_github_repo_name` or `Stack` lookup) that ties the verified org back to the acted-upon repository's owner; I found none in `app/models/shipit/webhooks/handlers/handler.rb`, `push_handler.rb`, `status_handler.rb`, or `check_suite_handler.rb`.

### Recommendation
- In `WebhooksController#verify_signature`, after establishing which org's app verified the request, cross-check that `repository.full_name`'s owner segment (or `organization.login`) actually matches the `repository_owner` used to select the verifying `GitHubApp`, and `head(422)` on mismatch.
- In `Shipit::Webhooks::Handlers::Handler`, thread the verified organization through to `stacks`/`repository_name` resolution and reject/ignore payloads whose repository owner doesn't match.
- In `StatusHandler`, scope the `Commit.where(sha: ...)` lookup by the verified repository/stack rather than matching bare SHA globally.
- Consider making `webhook_secret` mandatory (fail closed) rather than optional, or at minimum warn loudly / refuse ambiguous multi-repo actions when any org lacks a secret.

### Proof of Concept
Given a Shipit instance configured with (per `docs/setup.md` "Using Multiple Github Applications"):
```yaml
production:
  github:
    noauthorg:
      app_id: 1
      installation_id: 1
      # webhook_secret intentionally omitted
    victimorg:
      app_id: 2
      installation_id: 2
      webhook_secret: real-secret
```
1. Attacker (no credentials) sends:
```
POST /webhooks
X-Github-Event: status
Content-Type: application/json

{
  "sha": "<sha of a real commit in victimorg/victim-repo tracked by Shipit>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "noauthorg" }, "full_name": "victimorg/victim-repo" }
}
```
2. `verify_signature` calls `Shipit.github(organization: 'noauthorg')`, whose `verify_webhook_signature` returns `true` unconditionally because `noauthorg` has no `webhook_secret` [10](#0-9) .
3. `StatusHandler#process` matches `Commit.where(sha: params.sha)` for the real commit in `victimorg/victim-repo` and calls `create_status_from_github!`, injecting a forged "success" status for a required CI context on a stack the attacker has no relationship with [4](#0-3) , potentially satisfying merge-queue/deploy CI gating.

I was not able to execute this against a running instance (no filesystem/terminal access here); the flow above is derived directly from reading the cited source. If confirmation via a live run is needed, that would require a background Devin session with repo/terminal access, which is outside the scope of this read-only analysis.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** docs/setup.md (L71-71)
```markdown
    webhook_secret: some-secret-value
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
