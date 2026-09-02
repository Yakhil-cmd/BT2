### Title
Forged commit-status webhook from an unrelated GitHub App installation can mark any commit as CI-passing, enabling an unauthorized deploy - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate a webhook's HMAC against based on a field taken from the untrusted request body itself (`repository.owner.login` / `organization.login`), not from any value bound to a specific installation. `StatusHandler`, unlike the base `Handler` class and every other handler, never scopes its side effect to the repository named in the payload — it looks up `Commit.where(sha: params.sha)` globally across the entire database. Combined, an attacker who legitimately owns a GitHub App installation for *their own* organization (and therefore its `webhook_secret`) can forge a validly-signed `status` event whose `sha` refers to a commit belonging to a completely different, victim stack, injecting a fabricated "success" CI status for it.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

The organization used to pick the verifying `webhook_secret` is read straight out of the JSON payload that the attacker fully controls and signs themselves. Nothing ties this to an authenticated GitHub App installation ID delivered out-of-band — it's simply "whichever secret you can produce a valid HMAC for, using a body you also crafted." This is fine as a signing binding *if and only if* everything the handlers subsequently act on is also constrained to that same organization/repository. That constraint holds for `Handler#stacks`, which scopes lookups by `payload.dig('repository', 'full_name')`: [2](#0-1) 

But `StatusHandler` does not use `stacks`/`repository_name` at all:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

There is no repository/stack scoping — any `Commit` row anywhere in the Shipit instance whose `sha` matches `params.sha` gets a new `Status` row created from attacker-supplied `state`/`context`/`description`/`target_url`.

**The broken binding:** `organization authenticated for the webhook signature == organization/repository whose data is written`. Before the attack, this equality is assumed to hold because only the app's own installation secret is meant to authorize writes to that installation's repositories. After a crafted `status` event, the equality is broken: signature verification succeeds for org A (attacker's own installation), while the actual row mutated (`Status` on a `Commit`) belongs to stack/org B, entirely unrelated to A.

### Impact Explanation
Shipit's `ci.require`/`ci.blocking` mechanism (documented in `README.md`) and continuous delivery gate deploys on the presence of green `Status` records for a commit. `Status` rows are exactly what `StatusHandler` writes. An attacker who runs their own GitHub organization/repo, installs the same Shipit-configured GitHub App on it (a routine, unprivileged action any GitHub user can perform for their own repos), obtains that installation's `webhook_secret`, and then POSTs a forged `status` event naming a `sha` belonging to a victim's stack, can inject a fabricated passing CI status for a commit that never actually passed CI on GitHub. If continuous delivery is enabled on the victim stack, this can trigger an unauthorized deploy of that commit — satisfying the "Critical: unauthorized deploy" bar in the rules. This requires no session, no `ApiClient` token, and no privileged relationship with the victim organization; the only prerequisite is the attacker's own (unprivileged) GitHub App installation, which is explicitly the trust unit this endpoint is designed to authenticate.

### Likelihood Explanation
The webhook endpoint is unauthenticated by design (it authenticates via HMAC signature instead), and multi-organization support is a first-class, documented feature (`docs/setup.md`, "Using Multiple Github Applications"), meaning any Shipit deployment monitoring more than one org already has more than one valid `webhook_secret` an attacker in one of those orgs could exploit against the others. Even a single-org deployment is exposed if the attacker can register a GitHub App installation of their own that happens to authenticate against the same `Shipit.github` config path (e.g., GitHub Enterprise multi-tenant setups, or if the instance owner installs the Shipit app broadly). The core defect — `StatusHandler` skipping repository scoping while every sibling handler enforces it — is a straightforward code-review-detectable omission, and exploitation only requires knowing a target commit's `sha`, which is public information on GitHub.

### Recommendation
1. Scope `StatusHandler#process` to the repository named in the payload, mirroring the base `Handler#stacks`/`repository_name` pattern used elsewhere, e.g. restrict the `Commit.where(sha: params.sha)` lookup to commits belonging to stacks under `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`.
2. Independently of (1), stop deriving the signature-verification organization purely from attacker-supplied payload fields; bind webhook deliveries to a specific `GithubHook`/installation record (as `test/fixtures/shipit/github_hooks.yml` models with `Repo`/`Organization` hook types) and verify that the resolved organization/repository actually matches the target the handler is about to mutate before any write occurs.

### Proof of Concept
1. Attacker creates GitHub org/repo `attacker-org/attacker-repo`, installs the shared Shipit GitHub App there, and Shipit admin adds `attacker-org` to `config/secrets.yml`'s multi-org `github:` map (a normal, documented setup step), giving the attacker knowledge of `webhook_secret` for `attacker-org` (it's the secret they configured on their own GitHub App page).
2. Attacker identifies a target commit `sha` belonging to victim stack `victim-org/victim-repo` (public commit SHAs are visible on GitHub, and `Commit` rows are created by Shipit's regular git sync).
3. Attacker crafts a `status` event body:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/circleci",
  "organization": { "login": "attacker-org" }
}
```
4. Attacker signs it with `HMAC-SHA1(attacker-org webhook_secret, body)` and sets `X-Hub-Signature`, `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and successfully verifies the signature [4](#0-3) .
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` unconstrained by org/repo and writes a green `Status` for the victim's commit [3](#0-2) , which the victim stack's continuous-delivery/`ci.require` logic can treat as satisfied CI, causing an unauthorized deploy.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
