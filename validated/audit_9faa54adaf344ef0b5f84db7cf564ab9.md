### Title
Webhook signature verification is keyed off an unauthenticated payload field, letting a forged event for one (weakly-configured) GitHub organization mutate/deploy stacks belonging to a different, unrelated repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` derives *which* GitHub App/secret to use for HMAC verification from a value read straight out of the **unverified** request body (`repository.owner.login` / `organization.login`), then hands the very same unverified body to `Shipit::Webhooks.for_event(event)` handlers, which independently pick the target `Stack`/`Repository`/`Commit` to act on via `repository.full_name` (a completely different field of that same unverified body). Nothing binds "the organization whose secret validated this request" to "the repository the handler actually writes to." If any organization configured on this Shipit instance has no `webhook_secret` set, `GitHubApp#verify_webhook_signature` unconditionally returns `true` for that organization, so an attacker can pick that organization's login to sail through verification while pointing `repository.full_name` at a totally different, properly-configured stack.

### Finding Description
`verify_signature` computes the verification key like this: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`repository_owner` is read from `JSON.parse(request.raw_post)` **before** any signature has been checked - it is fully attacker-controlled. `Shipit.github(organization:)` looks up per-organization config and instantiates a `GitHubApp` scoped to whatever secret that organization has configured: [3](#0-2) 

`GitHubApp#verify_webhook_signature` treats a blank `webhook_secret` as automatically verified: [4](#0-3) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

So for any organization onboarded onto this Shipit instance without a configured `webhook_secret` (this is an explicitly supported, documented configuration - see `template.rb`, which generates `webhook_secret:` blank by default), signature checking is a no-op.

Once `verify_signature` passes, the same untrusted body is dispatched to handlers, none of which re-derive or re-check the organization used for verification. They instead independently resolve the target repository from `repository.full_name` in the payload: [5](#0-4) [6](#0-5) [7](#0-6) 

This is exactly the class of bug the report describes generalized to an authorization binding: the report's "hardcoded `minimum-amount-out`" is a value the contract *trusts implicitly with no cross-check against what actually happened*, resulting in loss. Here, the binding that should hold is:

`organization used to select/verify the webhook secret == organization/repository the handler is permitted to mutate`

but the code enforces no such equality - `repository_owner` (used for verification) and `repository.full_name` (used for the actual write) are two independent, both attacker-controlled, fields of the same JSON body.

### Impact Explanation
An attacker who knows (or can enumerate, e.g. via a public onboarding page, prior history, or simply by trying common/public org names) at least one GitHub organization configured on the target Shipit instance **without** a `webhook_secret` can:
1. Send a forged `X-Github-Event: status` (or `push`) webhook with `repository.owner.login`/`organization.login` set to the weakly-configured org (bypassing signature verification via the `return true unless webhook_secret` short-circuit), and
2. Set `repository.full_name` to a **different**, properly secured stack's repository, along with an attacker-chosen `sha`, `state: "success"`, `context`, `description`.

`StatusHandler#process` will then locate `Commit` records by `sha` across the whole install (it does not even filter by the handler's own `repository_name` - see `Handler#stacks`, unused here, versus `Commit.where(sha: params.sha)` in `StatusHandler`) and write a forged "success" status. For a stack with `continuous_deployment` enabled and CI requirements satisfied by this forged status, this can drive an **unauthorized deploy** of an unrelated repository/organization - meeting the Critical bar in the rules ("unauthorized deploy"). Even absent continuous deployment, it forges CI state that gates manual deploys, defeating the whole purpose of the `ci.require`/`ci.blocking` checks documented in the README.

The `PushHandler` path is similarly affected: `repository_name` for `Repository.from_github_repo_name` lookup and `stacks.not_archived.where(branch:).find_each { stack.sync_github(...) }` is driven entirely by the same forged, unverified `repository.full_name`, letting the attacker trigger syncs/deploy-consideration for arbitrary tracked stacks under a different org's signature domain.

### Likelihood Explanation
Likelihood is realistic in any multi-organization Shipit deployment (`Shipit.github_organizations`, `github_app_config`) where administrators onboard some orgs with a webhook secret and forget/omit it for others (the scaffolding in `template.rb` ships `webhook_secret:` empty by default, and nothing in `github_app_config`/`Shipit.github` enforces that all configured orgs have a secret). The attacker needs no credentials, no repo write access, and no session - only the ability to POST to the public `webhooks_controller#create` endpoint and knowledge of one weakly configured organization's login string (which may be discoverable from `Shipit.github_organizations`, public GitHub org membership, or by trial).

### Recommendation
- Require `webhook_secret` to be present for every configured GitHub organization; fail closed (`verified = false`) instead of `true` when it is blank, or refuse to boot/serve webhooks for organizations missing a secret.
- Bind verification identity to write scope: after `verify_signature` succeeds, re-derive the organization from the *verified* `repository_owner` and ensure every handler resolves its target `Stack`/`Repository`/`Commit` using that same verified organization - reject payloads whose `repository.full_name` organization differs from `repository_owner`.
- In `StatusHandler`, scope the `Commit.where(sha:)` lookup to commits belonging to the verified repository/organization instead of a global sha lookup.

### Proof of Concept
Preconditions: Shipit instance configured with orgs `acme-oss` (no `webhook_secret`) and `victim-org` (has `webhook_secret`, tracks stack `victim-org/victim-repo` with `continuous_deployment: true`).

```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=deadbeef   # any/garbage value

{
  "repository": {
    "owner": { "login": "acme-oss" },   // selects org with blank webhook_secret -> verify_webhook_signature short-circuits true
    "full_name": "victim-org/victim-repo"
  },
  "sha": "<real head sha of victim-org/victim-repo commit awaiting CI>",
  "state": "success",
  "context": "ci/required-check",
  "description": "forged",
  "created_at": "2026-09-01T00:00:00Z"
}
```

`verify_signature` calls `Shipit.github(organization: "acme-oss")`, which returns `true` unconditionally because `webhook_secret` is blank. `StatusHandler#process` then finds the matching `Commit` (looked up globally by `sha`, independent of `acme-oss`) belonging to `victim-org/victim-repo` and writes the forged `success` status, satisfying `ci.require`/`ci.blocking` and potentially triggering `trigger_continuous_delivery` for `victim-org`'s stack - an unauthorized deploy of a repository never covered by the (blank) secret the attacker actually satisfied.

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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
