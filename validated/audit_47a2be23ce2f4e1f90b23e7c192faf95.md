Confirmed: the signature-verification org and the repository actually acted upon are two independent lookups from the same untrusted, attacker-supplied JSON body, and nothing ties them together.

### Title
Webhook signature is verified against the payload's `repository.owner.login`, but the stack/repository actually mutated is selected from the same payload's `repository.full_name` — cross-organization signature confusion enables cross-repository writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to verify the HMAC against using `repository_owner`, taken from the unverified JSON body (`params.dig('repository','owner','login')`). Once verification succeeds, the handlers (e.g. `Shipit::Webhooks::Handlers::Handler#stacks`, `GithubSyncJob`) resolve the target `Stack`/`Repository` using a *different* field from the same body: `repository.full_name`, via `Repository.from_github_repo_name`. Because Shipit supports multiple configured GitHub organizations (`config.github` map, see `docs/setup.md`), an operator who legitimately owns one configured organization's `webhook_secret` can craft a payload whose `repository.owner.login` matches their own org (so the HMAC computed with their own secret verifies) while `repository.full_name` names a stack belonging to a different, victim organization also hosted on the same Shipit instance.

### Finding Description
- `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` from `params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)` [1](#0-0) [2](#0-1) .
- `verify_webhook_signature` only checks the HMAC-SHA1 of the raw body against the secret configured for *that* organization [3](#0-2) . It never checks that the body's `repository.full_name` belongs to that same organization.
- After verification, the actual body is dispatched to handlers, e.g. `Shipit::Webhooks::Handlers::Handler#stacks`, which resolves target stacks via `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository','full_name')` [4](#0-3) , and `Repository.from_github_repo_name` splits that string into `owner/name` and does a plain DB lookup with no relation back to the verified organization [5](#0-4) .
- Similarly, `push` events enqueue `GithubSyncJob` (see `test/controllers/webhooks_controller_test.rb:23-32`) keyed off a `stack_id` resolved from the payload's repository fields, and `GithubSyncJob#perform` fetches commits and writes them to whichever `Stack` was resolved [6](#0-5) , independent of which organization's secret validated the request.

This is exactly the bug class described in the external report: a value used to authorize/select a trust context (`repository.owner.login` → which org's secret validates the message) is not the same value later used to act (`repository.full_name` → which repository/stack is mutated). An attacker doesn't need "true randomness" broken here — they need only that the two fields are decoupled and both attacker-controlled inside one signed body, since the signature only proves "the sender knows organization A's secret," not "this event is about organization A's repository."

### Impact Explanation
An attacker who controls (or has compromised) the webhook secret/delivery for one organization configured in a multi-org Shipit deployment (`Shipit.github` supports a per-organization config map, `test/dummy/config/secrets_double_github_app.yml`) can forge a validly-signed webhook whose `repository.full_name` points at a stack owned by a *different* organization on the same instance. Depending on event type this can:
- Trigger `GithubSyncJob` to sync/append commits into a victim stack (`push`), influencing what is considered "deployable" head, an unauthorized write to that stack's commit/deploy state.
- Trigger PR-driven handlers (`pull_request/*_handler.rb`) that manipulate merge-queue state, labels, or review-stack provisioning for a victim repository.

This matches the "cross-repository writes" / "unauthorized deploy" impact tier: the write is not gated by anything proving the sender is authorized for the *target* organization's repository, only for some organization configured on the instance.

### Likelihood Explanation
Requires the instance to be configured with multiple GitHub organizations (a documented, supported configuration — see `docs/setup.md` "Use this configuration schema if you are configuring multiple Github applications"). Within that configuration, exploitation only requires knowledge of one org's `webhook_secret` (obtainable by anyone with admin access to that org's GitHub App settings, i.e., a legitimate but lower-privileged tenant of the shared instance) and the ability to send an arbitrary HTTP POST to the shared `/webhooks` endpoint with a crafted `repository` object — no GitHub API access to the victim org is needed. This is a realistic multi-tenant misconfiguration-adjacent path rather than requiring GitHub server compromise.

### Recommendation
After signature verification, re-derive the organization from the same field used for stack resolution (`repository.full_name`'s owner segment) and reject the request (422) if it doesn't match the organization whose secret validated the signature. Concretely, in `WebhooksController#verify_signature`, ensure `repository_owner` and the owner segment of `repository.full_name` (or `organization.login` for org-level events) are identical before accepting, or verify the signature using the org derived consistently from `full_name` rather than `owner.login`.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with distinct `webhook_secret`s (supported per `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker (owner of `attacker-org`'s GitHub App/webhook secret) builds a JSON body:
```json
{
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  },
  "after": "<attacker-chosen-sha>"
}
```
3. Compute `X-Hub-Signature: sha1=<hmac-sha1(attacker-org's webhook_secret, body)>`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and the HMAC verifies successfully (`app/controllers/shipit/webhooks_controller.rb:24-30`, `lib/shipit/github_app.rb:76-83`).
6. The push handler enqueues `GithubSyncJob` for the stack matched by `Repository.from_github_repo_name('victim-org/victim-repo')` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/repository.rb:53-56`), causing Shipit to sync/act on `victim-org/victim-repo`'s stack using a request never authorized by `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/jobs/shipit/github_sync_job.rb (L18-26)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }
```
