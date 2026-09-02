### Title
Webhook signature verification binds to `repository.owner.login`, not the `repository.full_name` actually written - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App/secret to validate an inbound webhook against using `repository_owner`, taken from the unverified JSON body itself. Once the signature check passes, every webhook handler resolves the `Repository`/`Stack` to mutate using a completely different, also attacker-supplied field: `repository.full_name`. Nothing cross-checks that the organization whose secret validated the signature actually owns the repository being written to, breaking the binding `organization that authenticated == repository that is written`.

### Finding Description
`verify_signature` computes the signing organization purely from payload data: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up a per-organization `GithubApp` config, and `verify_webhook_signature` is evaluated against that organization's own `webhook_secret`: [3](#0-2) 

Critically, if that organization has no `webhook_secret` configured, verification unconditionally succeeds (`return true unless webhook_secret`). Shipit supports being configured for multiple organizations (see the `GithubOrganizationUnknown` rescue path and multi-org lookup), so an attacker only needs write access to *any* GitHub org onboarded to this Shipit instance (or one left without a webhook secret) to obtain a validly-signed (or trivially-bypassed) webhook envelope.

However, none of the webhook handlers use `repository_owner` again. Every handler resolves the target repository independently from `repository.full_name`, a distinct field in the same payload that is never cross-checked against the verified owner: [4](#0-3) [5](#0-4) 

So the field that gates authentication (`repository.owner.login` / `organization.login`) and the field that gates authorization for the write (`repository.full_name`) are two different, independently attacker-controlled strings in the same unsigned-until-verified JSON body, and the signature only covers "this byte stream came from an org I trust," not "this byte stream is about a repository that org owns."

### Impact Explanation
This allows cross-repository/cross-tenant writes: an attacker who controls (or has push/webhook access to) one onboarded organization — or any organization configured without a `webhook_secret` — can send a forged webhook whose `repository.owner.login`/`organization.login` matches their own (permissive) org, while `repository.full_name` names a victim organization's repository. Handlers such as the pull-request handlers (`ReviewStackAdapter.find_or_create!`), membership/team handlers, and status handlers will act on the victim `Repository`/`Stack` — e.g. provisioning review stacks, altering commit statuses that gate deploys, or manipulating team membership tied to `Shipit.github_teams` authorization — even though the request was never authenticated for that victim organization. This is a cross-repository write triggered by a boundary the code assumes but never enforces, matching the "Critical: cross-repository writes" impact class.

### Likelihood Explanation
Exploitability requires the attacker to control (or have webhook-delivery rights on) at least one GitHub organization already configured in this Shipit instance — a materially lower bar than compromising the target victim organization, and trivial if any onboarded org lacks a `webhook_secret` (explicitly documented as optional in `docs/setup.md`). No Shipit session, API token, or GitHub App private key is needed; only a crafted HTTP POST to `/webhooks` with a body whose `owner.login`/`organization.login` differs from `repository.full_name`'s owner.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), require that the organization portion of `repository.full_name` matches `repository_owner`/the organization whose secret validated the signature, and reject the webhook (422) if they differ. Do not treat `repository.owner.login` and `repository.full_name` as independently trustworthy once only one of them has been checked against a secret.

### Proof of Concept
1. Shipit is configured for two GitHub Apps/orgs: `attacker-org` (no `webhook_secret` set, or one the attacker knows) and `victim-org` (hosts the real Shipit-tracked repository `victim-org/prod-app`).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: pull_request` and body:
```json
{
  "action": "opened",
  "organization": { "login": "attacker-org" },
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/prod-app" },
  "pull_request": { ... },
  "sender": { "login": "attacker" }
}
```
3. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and `verify_webhook_signature` succeeds (secret-less org, or attacker's own valid signature).
4. `OpenedHandler#repository` resolves `Shipit::Repository.from_github_repo_name("victim-org/prod-app")`, and the handler provisions/modifies review-stack state for the victim repository, even though the request was never authenticated for `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
