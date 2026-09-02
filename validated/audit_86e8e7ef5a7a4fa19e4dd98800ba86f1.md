### Title
Webhook signature is authenticated against `repository.owner.login`/`organization.login` while payload mutations key off the independent `repository.full_name`/commit `sha` fields, allowing an attacker who legitimately controls one onboarded GitHub organization's webhook secret to forge writes against any other repository tracked by the same Shipit instance - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` is used to validate `X-Hub-Signature` based solely on `repository_owner`, computed from `params.dig('repository','owner','login')` (or `params.dig('organization','login')` as fallback) [1](#0-0) [2](#0-1) . Once the HMAC check passes, `Webhooks.for_event` dispatches to handlers that resolve the target `Repository`/`Stack`/`Commit` using a completely different field of the same attacker-controlled JSON body: `payload.dig('repository', 'full_name')` in the generic `Handler#repository_name` base method (used by `PushHandler` and all `PullRequest::*` handlers), or bare `params.sha` in `StatusHandler` [3](#0-2) [4](#0-3) [5](#0-4) .

Because signature verification and repository targeting read two independently attacker-supplied fields of the same raw HTTP body, nothing in the engine enforces that `repository.owner.login` (used to pick the verifying secret) actually matches the owner encoded in `repository.full_name` (used to pick the mutated `Stack`)/or that the `sha` belongs to a commit owned by that organization. Shipit explicitly supports multi-tenant configuration where distinct GitHub organizations each have their own `webhook_secret` (documented in `config/secrets.development.example.yml:18-38` and `docs/setup.md`). An org administrator who legitimately controls their own org's GitHub App installation (and therefore its `webhook_secret`) can compute a valid HMAC over a forged raw body whose `repository.owner.login` is their own org (so `Shipit.github(organization: repository_owner)` picks their secret) but whose `repository.full_name` or `sha` fields point at a completely different, victim organization's repository/commit that is also configured on the same Shipit instance.

### Finding Description
The trust binding that should hold is:
`organization whose webhook_secret authenticated the request == organization/repository that the handler subsequently mutates`

Before the PR (i.e., as implemented today) these are computed from two disjoint, independently forgeable JSON paths:
- Authentication: `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` → selects `Shipit.github(organization: repository_owner)` → selects the `webhook_secret` used in `verify_webhook_signature` [6](#0-5) [7](#0-6) .
- Mutation target: `Handler#repository_name = payload.dig('repository', 'full_name')`, used to look up `Repository.from_github_repo_name(repository_name).stacks` for `PushHandler`/`PullRequest::*` handlers [3](#0-2) ; or, worse, `StatusHandler` doesn't even scope by repository at all - it looks up `Commit.where(sha: params.sha)` globally across the entire Shipit instance and calls `commit.create_status_from_github!(params)` [5](#0-4) .

Since HMAC-SHA1 verification only checks that the byte sequence of `request.raw_post` matches the secret associated with whatever organization the same payload claims ownership under `repository.owner.login`, an attacker who legitimately administers Org A (and thus possesses Org A's real `webhook_secret` because they installed the App on their own org) can self-sign an arbitrary HTTP POST to `/webhooks` where:
- `repository.owner.login = "org-a"` (drives secret selection → passes verification with their own secret)
- `repository.full_name = "org-b/victim-repo"` and/or `sha = "<any commit sha tracked in org-b's stacks>"` (drives the actual write)

This crosses exactly the boundary the engine is supposed to enforce: an org's webhook credential should only be able to act on that org's own repositories/stacks, not on repositories belonging to other organizations configured on the same instance.

### Impact Explanation
Using `StatusHandler`, any commit sha (from any repository tracked by Shipit) can have a forged CI status (`state`, `context`, `description`, `target_url`) injected via `commit.create_status_from_github!(params)`, regardless of which org's webhook_secret was used to authenticate the request. Since Shipit gates deploy safety/CI checks on commit `Status` records, this lets an attacker outside the victim repository's trust boundary fabricate green/red CI signal for a repository they do not control, which can influence whether legitimate stack maintainers believe a commit is deployable — a cross-repository write into another organization's data with real deployment-safety consequences.

Using `PushHandler` and the `PullRequest::*` handlers, an attacker can trigger `stack.sync_github`, archive/unarchive review stacks, or overwrite `github_pull_request` metadata for any repository present in the Shipit database, not just their own, because `Handler#repository_name` is derived from `repository.full_name` independent of the authenticated `repository_owner`.

This satisfies the "cross-repository writes" Critical-impact category: an unprivileged-relative-to-the-victim-org attacker (they only control their own org's webhook credential) can write into another org's `Stack`/`Commit`/`PullRequest` state without ever needing the victim org's `webhook_secret`, an `ApiClient` token, a Shipit session, or GitHub repository write access to the victim repo.

### Likelihood Explanation
Requires: (1) the Shipit deployment configured for multiple GitHub organizations (a documented, supported configuration per `docs/setup.md`/`config/secrets.development.example.yml`), and (2) the attacker being a legitimate administrator of at least one of those organizations (able to install a real GitHub App on their own org and therefore possess a genuine `webhook_secret` for it). Given that Shipit is often run centrally for many teams/orgs within a company, and any org admin can install the app and thus obtain a valid webhook secret for their own org, this is a realistic insider/low-privilege scenario, not a theoretical one. No interception, no private key, no session, and no victim-org credentials are needed.

### Recommendation
Bind signature verification and the resolved mutation target to the same authenticated identity. Concretely:
- After successfully verifying the signature for `repository_owner`, re-derive `repository_name`/`sha`-owning-repository and assert that its owner matches the verified `repository_owner` before dispatching to handlers, or
- Look up the `Repository`/`Stack` scoped by the verified organization only, rejecting payloads whose `repository.full_name` owner segment does not equal the `repository_owner` used to pick the webhook secret.
- For `StatusHandler`, scope the `Commit` lookup by repository (derived from the verified organization) instead of a bare global `sha` lookup.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `github.webhook_secret` (per documented multi-org config).
2. As the administrator of `org-a` (legitimately holding `org-a`'s `webhook_secret` because they installed the App), craft a raw JSON body for the `status` event:
```json
{
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-a/some-repo" },
  "sha": "<sha of a commit belonging to a stack in org-b>",
  "state": "success",
  "context": "ci/forged",
  "created_at": "2026-09-01T00:00:00Z"
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(org-a's webhook_secret, raw_body)>` and POST to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner = "org-a"`, fetches `org-a`'s app/secret, and the HMAC check passes (the attacker computed it correctly with their own known secret) [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` globally (no org/repo scoping) and calls `create_status_from_github!`, injecting a fabricated status onto a commit belonging to `org-b`, an organization the attacker does not administer [5](#0-4) .

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
