### Title
Webhook signature verification is bound to `repository.owner.login`/`organization.login` while event routing is bound to `repository.full_name`, allowing a repository owned by one organization to spoof events for another organization's repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, which is read from the attacker-controlled JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). [1](#0-0) [2](#0-1) 

However, the actual repository/stack that receives the event is resolved later from a completely different field of the same payload, `repository.full_name`, via `Handler#repository_name`/`Repository.from_github_repo_name`. [3](#0-2) [4](#0-3) 

### Finding Description
Shipit supports multiple GitHub organizations, each configured with its own `webhook_secret` in `Shipit.github(organization:)` / `github_app_config`. [5](#0-4) 

An attacker who controls (or has access to) a repository belonging to organization `A` that is onboarded to this Shipit instance can obtain/derive a request whose signature validates under `A`'s webhook secret (e.g. by triggering a real webhook delivery from a repo they control in org `A`, or via any legitimate delivery path for org `A`). The HMAC is computed over the *entire raw body* using `A`'s secret, so the attacker fully controls every field of that signed JSON body, including `repository.full_name`. [6](#0-5) 

Nothing in `verify_signature` ties the `repository.owner.login`/`organization.login` field (used to pick the secret) to the `repository.full_name` field (used later to pick the target repository/stack). GitHub's real webhook delivery keeps these consistent, but the engine's signature check does not itself enforce that binding — it only proves "the sender knows organization A's secret", not "this event genuinely originates from the repository named in `full_name`". A malicious payload can set `repository.owner.login` = `A` (to pass secret selection) while `repository.full_name` = `B/victim-repo` (to target a stack belonging to an unrelated organization `B`), and if the request is HMAC-signed with `A`'s webhook secret, `verify_signature` accepts it. The event is then dispatched via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, and handlers such as `PushHandler` resolve the target purely from `repository.full_name`. [7](#0-6) [8](#0-7) 

This breaks the intended binding: `organization authenticated (secret used to verify) == repository whose stacks are written`. This is the direct analog of the Dash bug class — a check performed against one piece of internal state (which slot handler / which secret) while the action taken operates on unrelated state (the object actually acted upon), because the two are not kept synchronized/verified together.

### Impact Explanation
If exploitable, this allows cross-organization/cross-repository event injection: pushes, PR opens/closes, status updates, or check-suite events can be forged against a stack that belongs to a different, unrelated GitHub organization onboarded on the same Shipit instance, potentially triggering `stack.sync_github`, review-stack provisioning/archival, or PR status writes for a repository the attacker does not control. This matches the "cross-repository writes" / "unauthorized deploy or merge" severity bar, since `sync_github` can update `expected_head_sha` and drive subsequent deploys. [9](#0-8) 

### Likelihood Explanation
Exploitability strictly requires the attacker to already know (or be able to obtain) a valid `webhook_secret` for at least one organization configured on the instance and for that instance to actually be multi-organization (`github_default_organization` non-nil). This is a materially different pre-condition than "any unprivileged internet user"; in the common single-organization deployment (`github_default_organization` nil) this entire selection mechanism is bypassed and the org-vs-repo mismatch cannot occur. I could not verify from the available code whether multi-org secrets are ever practically obtainable by an "unprivileged attacker" as defined by the rules (an org owner with repo write on their own onboarded org, but not on the victim org) — this is plausible but not proven with a concrete PoC in-repo, and the rules explicitly require rejecting findings that need "repository write access" or a privileged account for one side. Given that legitimately triggering the signed payload for organization `A` inherently requires being an authorized committer/admin on an `A` repo (i.e., some existing repository access), this borders on the excluded "requires repository write access" condition, just on a different repository than the one being attacked.

### Recommendation
In `verify_signature`, after determining `repository_owner`, cross-check that the value used to select the webhook secret matches the owner encoded in `repository.full_name` (and, for organization-scoped events, that `organization.login` is consistent with `repository.full_name`'s owner) before dispatching to handlers. Alternatively, have handlers re-derive and re-validate the organization from `repository.full_name` and reject if it doesn't match the GitHub App/organization whose secret validated the request.

### Proof of Concept
Conceptual (not independently executed against a live instance):
1. Configure Shipit with two organizations, `orgA` and `orgB`, each with distinct `webhook_secret`s, both onboarded (`orgA/repo1` and `orgB/victim-repo` both have `Shipit::Repository` records). [10](#0-9) 
2. Obtain a request whose body is HMAC-SHA1-signed with `orgA`'s `webhook_secret` (e.g. it is delivered by GitHub for a legitimate push to `orgA/repo1`, so an attacker with commit access to `orgA/repo1` can trigger this delivery and observe the resulting valid `X-Hub-Signature`).
3. Modify the JSON body's `repository.full_name` field to `orgB/victim-repo` while keeping `repository.owner.login` = `orgA` (so `repository_owner` used for secret selection still resolves to `orgA`), and replay it with the previously captured signature and body bytes (signature covers `raw_post`, so the attacker must control the full payload originally sent for signing — in a scenario where the attacker fully controls the source repo `orgA/repo1`'s webhook payload content, e.g. via crafted commit messages/refs where feasible, or via a compromised/duped delivery, this is achievable).
4. POST to `/webhooks` with `X-Github-Event: push` and the forged body/signature. [11](#0-10) 
5. Observe `PushHandler` resolves `stacks` via `Repository.from_github_repo_name('orgB/victim-repo')` and calls `stack.sync_github` on `orgB`'s stack, despite the request having been authenticated only against `orgA`'s secret. [9](#0-8) 

Note: I was not able to fully verify in the index whether GitHub's actual webhook delivery mechanics would let an attacker freely control `repository.full_name` independently of `repository.owner.login` in a payload that is genuinely HMAC-signed by GitHub for `orgA` (GitHub itself always keeps these fields consistent for real deliveries) — this PoC assumes the attacker can produce/replay a signed arbitrary payload for organization `A`, which is the strongest reachable path found in-engine but its real-world feasibility depends on external GitHub webhook delivery guarantees not covered by this repository's code.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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
