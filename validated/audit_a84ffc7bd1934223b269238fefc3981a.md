### Title
Webhook signature verification is bound to `repository.owner.login`, but handlers act on globally-unscoped or differently-scoped data — cross-repository status/commit spoofing - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The webhook signature check authenticates a request against the GitHub App configuration selected by the attacker-controlled `repository.owner.login` (or `organization.login`) field of the JSON body, while several webhook handlers act on data that is not scoped to that same organization/repository. In particular, `StatusHandler` looks up commits globally by SHA with no repository filter at all. Combined with the fact that a per-organization `webhook_secret` is optional (and unconditionally bypasses signature verification when unset), an unprivileged network attacker can spoof CI status for a commit belonging to a completely different, properly-secured repository, breaking the equality `organization that authenticated == repository that is written`.

### Finding Description
`WebhooksController#verify_signature` resolves the GitHub App/secret to check the signature against using a field taken directly from the untrusted request body: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — entirely attacker-controlled JSON content, not tied to any credential.

`Shipit.github(organization:)` resolves the app config for that org name, and `verify_webhook_signature` intentionally **bypasses signature checking entirely** when that org's `webhook_secret` is not configured: [3](#0-2) 

A missing `webhook_secret` is a documented, supported configuration (marked "optional" in setup docs and shown as `webhook_secret: # nil` in example secrets files): [4](#0-3) 

So, in any multi-organization Shipit deployment (`config/secrets` `github:` keyed by org, as shown in `secrets.development.shopify.yml`) where at least one configured organization has no `webhook_secret`, an attacker can craft a payload where `repository.owner.login` equals that unsecured org's name — this makes `verify_signature` accept the request unconditionally, regardless of the actual `X-Hub-Signature` header value.

Once past `verify_signature`, the handler that actually performs the write does **not** re-validate that the acted-upon repository/commit belongs to the organization that was used to authenticate. `StatusHandler#process` queries `Commit` globally by SHA with no repository or stack scoping whatsoever: [5](#0-4) 

Compare this to the base `Handler`, which does have a `repository_name`/`stacks` scoping helper based on `payload.dig('repository', 'full_name')`, but `StatusHandler` does not use it at all — it bypasses per-repository scoping entirely: [6](#0-5) 

Other handlers (e.g. `PushHandler`) do scope by `repository.full_name`, but that field is itself distinct from and unchecked against `repository.owner.login` used for signature selection — the attacker fully controls both independently in the same forged request: [7](#0-6) 

The binding that should hold is: *organization used to select/verify the webhook signature* == *organization/repository whose state is mutated*. This engine breaks that equality — the authentication decision is keyed off one payload field (`repository.owner.login`), while the mutation acts on unrelated or entirely unscoped data (`Commit.where(sha:)` in `StatusHandler`, or a different `repository.full_name` in other handlers).

### Impact Explanation
CI status is used by Shipit to gate deploys (`ci.require`, `ci.blocking` in `shipit.yml`, as documented in README). By forging a `status` webhook event that is authenticated against an organization with no `webhook_secret` configured, an unauthenticated attacker can inject a fabricated `success` status for any commit SHA already known/guessed to exist in the Shipit database — regardless of which real GitHub organization/repository it belongs to. This can satisfy required-status gating and enable an **unauthorized deploy** to proceed on a stack the attacker has no relationship to, meeting the Critical bar ("an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires: (1) the Shipit install use the multi-organization config schema with at least one organization lacking `webhook_secret` (a documented, legitimate configuration choice, e.g. a staging/demo org or an install that never set a secret), and (2) knowledge of a target commit SHA (obtainable from public GitHub commit history/PRs, which Shipit itself often links to in deploy pages). No authentication, session, or API token is needed — only an HTTP POST to the public `/webhooks` endpoint. This makes the likelihood realistic for any deployment mixing secured and unsecured organizations.

### Recommendation
- Do not allow attacker-supplied payload fields (`repository.owner.login`, `organization.login`) to select which secret is used for signature verification without cryptographic binding; instead, verify the signature against all configured secrets/apps and only use the result if verification succeeds, or require a secret for every configured organization.
- In every handler that mutates state (especially `StatusHandler`), scope the lookup (`Commit`, `Stack`) to the repository/organization identified in the verified payload, matching the pattern already used in `Handler#stacks`/`repository_name`, instead of performing global, unscoped queries.
- Consider making `webhook_secret` mandatory when the multi-organization schema is used, since an unset secret silently disables signature verification for that organization.

### Proof of Concept
1. Configure Shipit with two organizations: `secure-org` (has `webhook_secret` set) tracking `secure-org/app`, and `open-org` (no `webhook_secret`) tracking any repo.
2. Attacker (no credentials) sends:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything

{
  "repository": { "owner": { "login": "open-org" } },
  "sha": "<victim commit sha from secure-org/app>",
  "state": "success",
  "context": "ci/required-check"
}
```
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "open-org")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`) — the bogus signature header is never actually checked.
4. `StatusHandler#process` runs `Commit.where(sha: params.sha)` with no organization/repository filter (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), finds the commit belonging to `secure-org/app`, and creates a spoofed `success` status on it — even though the request was never validated against `secure-org`'s secret.
5. If `secure-org/app`'s `shipit.yml` lists `ci/required-check` under `ci.require`/`ci.blocking`, this forged status can unblock/trigger a deploy for that stack.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
