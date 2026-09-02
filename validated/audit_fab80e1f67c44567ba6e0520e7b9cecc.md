Found the analog. The `StatusHandler` matches GitHub commit statuses by `sha` alone across the entire Shipit instance, without any binding to the repository/organization that the verified webhook signature was checked against.

### Title
Cross-repository commit status forgery via webhook `sha` lookup unbound from verified organization - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The `WebhooksController` verifies an inbound GitHub webhook's HMAC signature using a secret selected by the `repository_owner`/`organization` fields parsed from the JSON payload [1](#0-0) . Signature verification only proves the payload was signed by the secret configured for *that* organization; it says nothing about which `Commit` records the handler is allowed to touch. `StatusHandler#process`, however, ignores the repository/organization entirely and updates **every** `Commit` in the database whose `sha` matches the payload, regardless of which stack/repository owns that commit [2](#0-1) .

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` looks up the GitHub App/organization config via `Shipit.github(organization: repository_owner)` and verifies `X-Hub-Signature` against that organization's `webhook_secret` [3](#0-2) . This establishes the equality "organization whose secret authenticated the payload == organization asserted in the payload's `repository.owner.login`/`organization.login` field" — but it does **not** establish "repository whose commits get written == that organization's repository."

Once verified, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full, attacker-controlled JSON body to the `status` handler [4](#0-3) . `StatusHandler` only requires `sha` and `state`; it never validates `repository` against a stack scoped to the authenticating organization, and matches commits with a bare `Commit.where(sha: params.sha)` [5](#0-4) .

Because git SHAs are content-addressed and frequently shared (identical commits, cherry-picks, empty/boilerplate commits, or an attacker who forks/mirrors a targeted victim stack's public repository to reproduce an identical SHA), an attacker who legitimately controls **any** organization onboarded to this Shipit instance (with its own valid `webhook_secret`) can send a signed `status` webhook whose `sha` coincides with a commit tracked by a completely different, unrelated stack belonging to another organization. The signature check passes (it's valid for the attacker's own org), but `StatusHandler` writes a forged CI status onto the victim's `Commit` for any/all stacks that happen to contain that SHA — breaking the binding "organization that authenticated the payload == repository being written."

This mirrors the reported bug class: a value (organization/repository identity) is verified once, but a downstream write operation (`create_status_from_github!` on all matching commits) is not re-scoped to that verified identity, producing state that is inconsistent with what was actually authenticated.

### Impact Explanation
A forged commit status can flip `Commit#deployable?`/CI-required-status checks used to gate deploys and continuous delivery on a victim's stack (see `required_statuses`/`hidden_statuses` in `DeploySpec`), enabling an unauthorized deploy to be triggered on a stack the attacker does not own, satisfying the "unauthorized deploy" high/critical impact criterion. This is a cross-repository/cross-organization write achieved purely from an unprivileged webhook sender who legitimately owns some other organization's webhook secret, not the victim's.

### Likelihood Explanation
Requires only that the attacker operate any organization/repository already integrated with this Shipit instance (a common multi-tenant deployment) and produce or await a colliding SHA with a targeted stack's tracked commits — plausible via forks, cherry-picks, or repeated boilerplate commits (e.g., version bumps, merge commits, empty commits) rather than needing a cryptographic hash collision.

### Recommendation
Scope `StatusHandler#process` (and any other webhook handler that matches by `sha` alone) to commits belonging to stacks whose repository matches the `repository`/`organization` fields verified against the webhook signature, e.g. join through `Stack`/`Repository` filtered by `repository_owner`/`repo_name` from the verified payload, instead of a global `Commit.where(sha: ...)` lookup.

### Proof of Concept
1. Attacker registers/controls organization `attacker-org` on the Shipit instance, with its own valid GitHub App installation and `webhook_secret`.
2. Attacker crafts a commit (e.g., an empty commit, or a copy of a well-known boilerplate commit) whose SHA matches a commit already tracked in victim stack `victim-org/app` (e.g., via a fork, a shared vendored file, or an identical empty/merge commit).
3. Attacker sends a `status` webhook from `attacker-org`'s repository with `sha` set to the colliding SHA and `state: success`, signed with `attacker-org`'s valid webhook secret via `X-Hub-Signature`.
4. `WebhooksController#verify_signature` succeeds because the signature is valid for `attacker-org`.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, which matches the victim's commit too and creates a forged successful status on it, potentially unblocking a deploy gated on that CI status.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
