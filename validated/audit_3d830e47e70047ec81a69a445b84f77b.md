Now I have enough to confirm the vulnerability. Key finding: `StatusHandler` at [1](#0-0)  looks up commits globally by `sha` alone, with no repository/owner scoping whatsoever — unlike `PushHandler` or `CheckSuiteHandler` which at least scope via `Handler#stacks` (`Repository.from_github_repo_name(payload.dig('repository','full_name'))`). Combined with `WebhooksController#verify_signature`, which authenticates the payload only against the org derived from `repository.owner.login`/`organization.login` [2](#0-1) [3](#0-2) , this creates the exact binding break the rules describe: the organization whose secret authenticated the webhook is never checked against the repository/commit actually written to.

### Title
Webhook `status` event forges commit status on any tracked commit regardless of signing organization - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates an inbound webhook using only the GitHub organization named in the payload's `repository.owner.login` (or `organization.login`) field, fetching that organization's configured `webhook_secret` and checking the HMAC over the raw body. Once verified, the entire raw payload — including the `sha` field — is handed to the registered handler for the event type. `StatusHandler#process` uses `Commit.where(sha: params.sha)` with **no repository or stack scoping at all**, unlike other handlers (`PushHandler`, `CheckSuiteHandler`) which resolve the acted-upon repository via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`. The signature only proves "this body was signed by organization X's secret"; it proves nothing about which commit/repository the body's `sha` refers to.

### Finding Description
In a multi-tenant Shipit deployment (as documented/supported by `config/secrets.development.shopify.yml`, which configures multiple independent GitHub orgs, each with its own `webhook_secret`), the trust binding that must hold is:

`organization whose webhook_secret authenticated the request == organization owning the repository/commit that the handler mutates`

This binding is never checked:

- `WebhooksController#verify_signature` selects the signing organization purely from `repository_owner`, itself read straight from the untrusted, only-partially-verified JSON body: [2](#0-1) [3](#0-2) 
- `StatusHandler#process` then trusts the `sha` field from that same body to find and mutate **any** `Commit` record system-wide, with zero repository/org check: [1](#0-0) 

Since `sha` is a git commit hash, and hashes for a well-known open-source dependency or a leaked/observed commit SHA from another tenant's repository can be known or brute-forced/observed (e.g., via the target's public PR/status pages, or push webhooks the attacker also receives events for from their own org), an attacker who controls their own onboarded GitHub organization (and thus legitimately knows their own org's `webhook_secret`, which they set themselves when creating their GitHub App per `docs/setup.md`) can sign an arbitrary payload with their own valid secret, since verification never compares "org that signed" against "repository the `sha` belongs to." This lets them create/replay a `status` event whose `sha` belongs to a commit tracked under a *different* tenant/org's stack.

Compare to `PushHandler`/`CheckSuiteHandler`, which correctly scope to `Repository.from_github_repo_name(payload.dig('repository','full_name'))` before acting [4](#0-3)  — `StatusHandler` omits this scoping entirely.

### Impact Explanation
`Commit#create_status_from_github!` writes a `Status` row that directly feeds `Commit#deployable?` (`!locked? && (stack.ignore_ci? || (success? && !blocked?))`) [5](#0-4)  and can trigger continuous deployment via `add_status`'s `stack.schedule_merges` / deployable-status hook path [6](#0-5) . An attacker who only controls their own tenant/org's webhook secret can therefore forge a `success` CI status on a commit belonging to a completely different organization's stack, bypassing that stack's required CI checks and enabling an **unauthorized deploy** — matching the report's Critical impact bar.

### Likelihood Explanation
Requires the host application to run Shipit in a multi-organization configuration (explicitly supported, e.g. `config/secrets.development.shopify.yml` shows two independent orgs each with a `webhook_secret`). The attacker needs no privileged Shipit credentials (no `ApiClient` token, no session, no repository write access) — only legitimate control of their own onboarded GitHub App/org's webhook secret, which they themselves configure. They additionally need the target commit's SHA, which is routinely public (GitHub commit URLs, CI logs, PR pages) even for repos they can't write to.

### Recommendation
In `StatusHandler#process` (and any other handler that trusts payload identifiers without repository scoping), resolve the acted-upon repository from `payload.dig('repository', 'full_name')` via the shared `Handler#stacks`/`Repository.from_github_repo_name` helper and restrict the `Commit` lookup to `stacks.commits` (or otherwise verify `repository_owner` used for signature verification matches the repository owning the commit) before creating/mutating a `Status`.

### Proof of Concept
1. Configure Shipit with two orgs, `attacker-org` and `victim-org`, each with distinct `webhook_secret`s (as supported by `Shipit.github(organization:)` config).
2. Attacker knows `attacker-org`'s own webhook secret (they configured it).
3. Attacker learns the SHA of a commit tracked in a `victim-org` stack (public GitHub info).
4. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, body `{"sha": "<victim-commit-sha>", "state": "success", "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/some-repo"}}`, signed with `attacker-org`'s secret as `X-Hub-Signature`.
5. `verify_signature` resolves `repository_owner` = `attacker-org`, fetches `attacker-org`'s `webhook_secret`, verification succeeds.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit (no owner check), and calls `create_status_from_github!`, injecting a forged `success` status that can flip `deployable?` to true and trigger continuous deployment on `victim-org`'s stack.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
