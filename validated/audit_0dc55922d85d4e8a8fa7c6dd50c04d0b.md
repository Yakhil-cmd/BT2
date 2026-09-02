### Title
Cross-repository status forgery bypasses organization-bound webhook signature, enabling unauthorized auto-deploy - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates an incoming webhook using the secret of the **organization named inside the payload** (`repository.owner.login`), but the handler that acts on the payload (`StatusHandler`) selects the **commit to mutate purely by `sha`**, with no check that the commit belongs to a stack/repository owned by the organization whose secret validated the signature. This breaks the intended binding "organization authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to validate the HMAC against using `repository_owner`, derived from the payload itself: [1](#0-0) [2](#0-1) 

The HMAC only proves the raw body was signed with *some org's* configured `webhook_secret` — it says nothing about which repository the enclosed data may reference. Since Shipit supports multiple GitHub organizations each with its own `webhook_secret` (documented in `docs/setup.md`), an attacker who legitimately installs their own Shipit GitHub App on their own organization (an "unprivileged" org relative to the target) knows that org's `webhook_secret` and can therefore produce a **validly signed** webhook body of their own choosing, including a `sha` field pointing at a commit belonging to an entirely different tenant's repository.

`StatusHandler#process` then resolves the target purely by `sha`, globally, without any repository/organization scoping: [3](#0-2) 

Unlike `PushHandler`/pull-request handlers, which at least scope through `Handler#stacks` → `Repository.from_github_repo_name(repository_name)`: [4](#0-3) 
`StatusHandler` never consults `repository_name`/`stacks` at all, so the organization used to validate the signature is completely decoupled from the commit/stack that is actually written.

**Binding broken:** `organization authenticated (via verify_signature using repository_owner’s webhook_secret)` ≠ `repository/commit actually written (any Commit row matching an attacker-chosen sha, unconstrained by organization)`.

Before the attacker's forged request: commit `X` belonging to Org B's stack has its real CI status (e.g., `pending`/`failure`).
After the attacker's forged request (signed with Org A's own, legitimately-known secret, event=`status`, body containing `sha` = commit `X`'s sha, `state` = `success`, matching `context`): `Commit#create_status_from_github!` creates a `success` Status row for commit `X` in Org B's stack, even though the signature only proves knowledge of Org A's secret.

### Impact Explanation
If Org B's stack has `continuous_deployment: true` and gates on a required CI `context`, this forged success status can satisfy the deploy gating logic and cause Shipit to auto-deploy an untested/attacker-influenced commit to Org B's stack — an unauthorized deploy triggered purely by a party that controls no more than their own, unrelated GitHub App installation. This matches the Critical impact category "an unauthorized deploy, rollback or merge."

### Likelihood Explanation
Requires only that the attacker operate their own GitHub organization with a Shipit-integrated GitHub App (a normal, unprivileged setup step available to any Shipit tenant in a multi-org deployment) and know the target stack's tracked commit SHA (visible in the target's public/private commit history or Shipit UI). No access to the target org's secret, no Shipit session, and no `ApiClient` token is needed — only the ability to send an HTTP POST to `/webhooks` signed with a secret the attacker legitimately possesses for their own tenant.

### Recommendation
`StatusHandler` (and any other handler that doesn't already scope through `Handler#stacks`) should validate that the resolved `Commit`'s `Stack`/`Repository` matches the `repository.full_name` in the payload, and that `repository.full_name`'s owner matches the organization (`repository_owner`) whose secret was used to verify the signature in `verify_signature`. More generally, `WebhooksController#verify_signature` should assert equality between the organization used to select the webhook secret and the organization implied by `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Attacker registers/owns GitHub organization `attacker-org` and installs their own Shipit-configured GitHub App on it, giving them the legitimate `webhook_secret` for `attacker-org` as configured in Shipit's `config/secrets.yml`.
2. Attacker identifies a tracked commit `sha=abc123` belonging to victim stack `victim-org/victim-repo` (context `ci/build`) that is pending/failing.
3. Attacker crafts a `status` event JSON body: `{"sha":"abc123","state":"success","context":"ci/build","repository":{"owner":{"login":"attacker-org"},"full_name":"attacker-org/some-repo"}}`.
4. Attacker computes `X-Hub-Signature: sha1=<hmac>` using `attacker-org`'s known `webhook_secret` and POSTs to `/webhooks` with header `X-Github-Event: status`.
5. `verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and successfully verifies the signature (line `app/controllers/shipit/webhooks_controller.rb:24-30`).
6. `StatusHandler#process` runs `Commit.where(sha: 'abc123').each { ... create_status_from_github! }` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), creating a spoofed `success` status on the victim commit regardless of it belonging to `victim-org`, potentially unblocking continuous auto-deploy for `victim-org/victim-repo`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
