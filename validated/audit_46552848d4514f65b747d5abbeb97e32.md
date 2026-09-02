### Title
Cross-organization forged commit-status webhook due to signature-authenticated organization ≠ repository being written - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature against using `repository_owner`, a field read from the untrusted JSON body itself (`repository.owner.login`, falling back to `organization.login`). Once the signature passes, the handler that actually mutates state — `Shipit::Webhooks::Handlers::StatusHandler` — never re-checks that same organization/repository binding: it looks up commits globally by SHA (`Commit.where(sha: params.sha)`) across the entire Shipit installation. In a multi-tenant Shipit instance (the documented setup allows one `github:` entry per organization, each with its own `webhook_secret`, see `config/secrets.development.shopify.yml` and `docs/setup.md`), any organization admin who legitimately knows their **own** organization's `webhook_secret` can sign an arbitrary POST body that declares their own org in `repository.owner.login` (so signature verification passes) while embedding a commit SHA that belongs to a **different** tracked repository/organization. Shipit will happily write a forged commit status for that unrelated repository's commit.

### Finding Description
- `verify_signature` fetches the GitHub App config solely from a payload-controlled field: [1](#0-0) [2](#0-1) 

- `StatusHandler#process` never consults `repository_name`/`stacks` (the org/repo-scoping helper defined on the base `Handler`) and instead resolves target commits purely by SHA, globally: [3](#0-2) [4](#0-3) 

- The signed HMAC only proves "this body was produced by whoever holds the secret for `repository.owner.login`" — it says nothing about whether the `sha` inside that body actually belongs to a commit owned by that same organization. `StatusHandler` treats any commit with a matching SHA anywhere in the Shipit database as fair game.

The broken equality is:
`organization whose webhook_secret authenticated the request` ≠ `organization/repository owning the commit whose status gets written`.

Because config supports multiple independent organizations each with a distinct GitHub App/`webhook_secret` (`docs/setup.md` lines 61-105, `config/secrets.development.shopify.yml`), a customer/org-admin who is fully entitled to know and use *their own* org's webhook secret (that's the credential model of the feature) can forge events that are authenticated as "from my org" but semantically target a repository belonging to a different tenant. This is not the "attacker already has a valid webhook_secret for the target" case excluded by the rules — the attacker has a valid secret for a *different, unrelated* organization and is abusing the SHA-only lookup to cross that boundary.

### Impact Explanation
`Commit#create_status_from_github!` persists a `Status` record (state/context/description/target_url) driven entirely by attacker-controlled webhook body fields, for a commit in a repository/organization the attacker's own webhook secret has no legitimate authority over. Shipit deployability gating relies on commit CI status (`deployable_status` is a first-class hook event in `app/models/shipit/hook.rb`'s `EVENTS` list), so a forged "success" status can mark an unrelated repository's commit as CI-green, feeding directly into deploy-gating decisions for that other tenant's stack. This matches the High-severity class "escalation into ... deployable_status" from the rules, since it lets an org-A credential holder falsify state relevant to org-B's deploy authorization without any repository write access, GitHub token, or session on org B.

### Likelihood Explanation
Requires only knowledge of one's own organization's `webhook_secret` (the credential a Shipit-hosted organization's admin is expected to hold to configure their GitHub App) plus knowledge/guessing of a target commit SHA in another tenant's repository (SHAs are often public/knowable, e.g. via GitHub itself). No repository write access, GitHub App private key, or Shipit session is needed — only the ability to POST to `/webhooks` with a self-signed payload for one's own tenant while pointing the payload's semantic content (SHA) at another tenant's commit.

### Recommendation
After signature verification, re-derive the authorized organization from the verified signature context and enforce it downstream: `StatusHandler` (and any other handler that doesn't already scope through `repository_name`) must join through the actual `Commit -> Stack -> Repository` chain and assert that repository's owning organization matches the organization whose secret authenticated the request, rejecting mismatches instead of trusting the bare `sha`.

### Proof of Concept
```
POST /webhooks HTTP/1.1
X-Github-Event: status
X-Hub-Signature: sha1=<HMAC-SHA1 of body using OrgA's known webhook_secret>

{
  "sha": "<commit sha that belongs to OrgB's tracked repository>",
  "state": "success",
  "context": "ci/required-check",
  "description": "forged",
  "repository": { "owner": { "login": "OrgA" } }
}
```
`verify_signature` resolves `Shipit.github(organization: "OrgA")`, verifies successfully with the attacker's own known secret, then `StatusHandler` runs `Commit.where(sha: params.sha)` and calls `create_status_from_github!` on any matching commit — regardless of which organization/repository it actually belongs to.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
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
