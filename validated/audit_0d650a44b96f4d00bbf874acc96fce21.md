### Title
Unauthenticated cross-repository webhook forgery via organisation/repository binding mismatch - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController` selects the GitHub App / webhook secret used to verify an inbound webhook's HMAC signature using the organisation login found in the payload, but every webhook handler resolves the **target** repository/stack from a completely different, unrelated field of the same attacker-controlled payload. These two values are never cross-checked, and signature verification silently no-ops for any organisation that has no `webhook_secret` configured, letting an unprivileged attacker impersonate GitHub for a repository they have no relationship to.

### Finding Description
`WebhooksController#verify_signature` derives the organisation solely from the payload: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) — a value the client fully controls. It is used only to pick which `GitHubApp` (and thus which `webhook_secret`) to verify against: [3](#0-2) 

Crucially, `verify_webhook_signature` returns `true` unconditionally when the resolved organisation has no `webhook_secret` configured — i.e. no cryptographic check happens at all for that org.

Meanwhile, every handler picks the *actual* repository/stack to act on from a different, independently attacker-controlled field: [4](#0-3) 

`repository_name` comes from `payload.dig('repository', 'full_name')`. Nothing enforces that this matches `repository.owner.login`/`organization.login` used for signature verification. Handlers such as `PushHandler` then act directly on whatever stack matches that `full_name`: [5](#0-4) 

This is a genuine binding break: **organisation authenticated (via `repository.owner.login` + its `webhook_secret`) ≠ repository written (via `repository.full_name` used to locate the `Stack`)**. In a multi‑org Shipit deployment (a documented, supported configuration — see `docs/setup.md`, "Using Multiple Github Applications"), any single organisation entry that has no `webhook_secret` set becomes a "skeleton key": an attacker crafts a payload with `repository.owner.login`/`organization.login` set to that secret‑less organisation (bypassing HMAC verification entirely) while setting `repository.full_name` to any *other* repository already registered as a `Stack` in the same instance — including ones belonging to properly‑secured organisations. The `status`/`push`/`check_suite` handlers then trust the forged payload at face value (e.g. `status` events create a `CommitStatus` directly from payload fields with no additional GitHub API cross-check, per `test/controllers/webhooks_controller_test.rb:42-59`), letting the attacker drive commit sync, deployment status updates, and — for stacks with `continuous_deployment: true` — trigger real deploys through `Deploy#complete!`/CD jobs that run with the app's real `GITHUB_TOKEN`.

### Impact Explanation
An attacker with no Shipit session, no API token, and no knowledge of the target repository's real webhook secret can forge GitHub webhook events for a repository whose organisation has a properly configured secret, purely by targeting the request at a differently-named organisation entry that lacks one. This can inject fake commit statuses, drive `GithubSyncJob`, and — where continuous deployment is enabled — cause an unauthorized deploy to run on the deploy host, using Shipit's own `GITHUB_TOKEN` for that unrelated repository. This meets the Critical bar for "unauthorized deploy" / "cross-repository writes."

### Likelihood Explanation
Exploitability depends on the specific deployment: it requires (a) multi-org configuration and (b) at least one configured organisation without a `webhook_secret`, or a single-org deployment run with no `webhook_secret` set at all (which the code explicitly tolerates, per `return true unless webhook_secret`). Given that `webhook_secret` is optional in the documented configuration surface and nothing in the code enforces cross-consistency between the authenticated organisation and the written repository, this is a realistic misconfiguration rather than a contrived edge case, but it is not universally exploitable against every deployment.

### Recommendation
Enforce that the organisation used to select/verify the webhook secret matches the owner of the repository the handler will act on (e.g. derive the target repository strictly from the same trust-verified organisation, or reject payloads where `repository.full_name`'s owner segment differs from the verified `repository.owner.login`/`organization.login`). Additionally, make `webhook_secret` mandatory for every configured organisation (fail closed instead of `return true unless webhook_secret`).

### Proof of Concept
1. Configure Shipit in multi-org mode with two organisations: `secure-org` (has `webhook_secret` set) and `open-org` (no `webhook_secret`), each per `docs/setup.md`'s multi-org example.
2. Register a `Stack` for `secure-org/critical-repo`.
3. As an unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<any tracked commit sha of critical-repo>",
  "state": "success",
  "target_url": "https://evil.example.com",
  "repository": { "full_name": "secure-org/critical-repo", "owner": { "login": "open-org" } }
}
```
4. `verify_signature` resolves `repository_owner` = `open-org`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (absent/invalid) `X-Hub-Signature` header.
5. The `status` handler processes the payload using `repository.full_name` = `secure-org/critical-repo`, creating a forged `CommitStatus` for that stack, potentially triggering continuous deployment if configured.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-35)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

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
