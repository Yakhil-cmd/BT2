### Title
Webhook signature is verified against the payload's `repository.owner.login` (or `organization.login`) while every event handler resolves and mutates state using the payload's `repository.full_name` — an unauthenticated field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App / HMAC secret to validate a webhook using `repository_owner`, derived from `params.dig('repository','owner','login')` (falling back to `organization.login`). Every handler that actually performs the mutating action (`PushHandler`, PR handlers such as `ClosedHandler`, etc.) instead resolves the target repository/stack via `Repository.from_github_repo_name(params.repository.full_name)` — a separate, unauthenticated field of the same JSON body. The signature only proves "this body was sent by whoever holds the secret for `repository.owner.login`"; it proves nothing about `repository.full_name`, which is what determines which stack is actually acted upon.

### Finding Description
`Shipit.github(organization:)` supports multi-organization deployments where each configured GitHub organization has its own `webhook_secret` (`lib/shipit.rb:170-200`, `config/secrets.development.example.yml`). Incoming webhooks are authenticated in `WebhooksController#verify_signature`: [1](#0-0) [2](#0-1) 

The organization used to select the HMAC secret is taken from `params.dig('repository','owner','login')` (or `organization.login`), which is an **unverified, attacker-controlled field of the very payload the signature is supposed to protect** — it is read out before the signature check even runs, purely to decide which secret to verify against.

Once the signature check passes, every handler ignores `repository.owner.login` entirely and instead derives the target repository from `repository.full_name`: [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

There is no code path anywhere that cross-checks `repository.owner.login` (the field used to pick the verifying secret) against `repository.full_name` (the field used to pick the stack that gets acted on). This breaks the equality: `organization authenticated by signature == organization whose repository is written to`.

Concretely, in a multi-org Shipit installation, an attacker who legitimately controls/administers **their own** GitHub organization "Org A" (and thus knows or can obtain the `webhook_secret` configured for Org A, e.g. by installing the app themselves and reading Delivery Details in GitHub's UI, or simply being the org admin who configured it) can craft an arbitrary webhook JSON body where:
- `repository.owner.login` = `"org-a"` (so `Shipit.github(organization: "org-a")` is used and the HMAC computed with Org A's secret verifies), and
- `repository.full_name` = `"victim-org/victim-repo"` (an entirely different, unrelated organization/repository tracked by the same Shipit instance).

Because `verify_webhook_signature` only checks the HMAC of the raw body against Org A's secret (which will match, since the attacker crafted and signed the body themselves), and no handler ever confirms that `full_name`'s owner segment equals `repository.owner.login`, the forged event is accepted and dispatched against the victim's stack.

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" boundary explicitly called out as in-scope. Depending on the handler abused, this allows an attacker who only controls a foreign/unrelated GitHub organization (with its own Shipit-configured webhook secret) to:
- Forge `push` events (`PushHandler`) to trigger `stack.sync_github(expected_head_sha:)` on another organization's stack for an arbitrary branch/SHA, spoofing sync state for a repository they don't own.
- Forge `pull_request` "closed" events (`ClosedHandler`) to archive review stacks belonging to another organization's repository.
- Forge `status`/`check_suite`/`membership` events against commits, teams, and memberships tied to repositories/organizations outside the attacker's control.

This is a cross-repository/cross-organization state-mutation primitive reachable without any Shipit session, `ApiClient` token, or privileged account on the victim's org — only knowledge of a secret for *any* organization configured on the shared Shipit instance is required. This matches the in-scope "cross-repository writes" impact category.

### Likelihood Explanation
High, in any multi-organization Shipit deployment (the documented supported configuration in `config/secrets.development.example.yml`). Any organization admin who is legitimately entitled to a webhook secret for their own org — a low, unprivileged bar relative to the victim org — can exploit this with a single crafted HTTP POST; no additional access or race condition is required.

### Recommendation
After signature verification, explicitly assert that the organization used to select/verify the secret (`repository.owner.login` / `organization.login`) matches the owner segment of `repository.full_name` before dispatching to any handler, and reject the request (422) on mismatch. Alternatively, derive the authenticating organization strictly from `repository.full_name` itself (single source of truth) rather than from a separate payload field.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `victim-org`, each with its own `github.webhook_secret` (multi-org schema per `lib/shipit.rb#github_app_config`).
2. Attacker (who administers `org-a` and knows `org-a`'s `webhook_secret`) crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(org-a secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")` and successfully verifies the signature against the attacker's own secret (`app/controllers/shipit/webhooks_controller.rb:24-30,59-62`).
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/repository.rb:53-56`) and invokes `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack — despite the request never being signed by `victim-org`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
