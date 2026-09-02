### Title
Webhook signature is verified against the payload's `repository.owner.login`/`organization.login` while every event handler acts on the unauthenticated `repository.full_name` field — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is the same trust-binding flaw as the report's "donation is sandwichable" bug: a value used to *authorize* an action (the org whose secret validated the signature) is not the same value the code subsequently *acts on* (the repository actually written to). In `UpliftOnlyExample`, fee accounting trusted a value (accrued/stepwise donation) that wasn't bound to the actor performing the withdrawal, letting an unrelated party capture it. Here, `WebhooksController#verify_signature` picks the GitHub App/webhook secret to validate against using `repository_owner` (`repository.owner.login`, falling back to `organization.login`), but the resulting `params` hash is handed unmodified to handlers that key their actions off `repository.full_name` — a JSON field the signature check never singles out or cross-validates against the org that supplied the matching secret.

### Finding Description
`WebhooksController#verify_signature` computes: [1](#0-0) 

using `repository_owner`: [2](#0-1) 

`Shipit.github(organization:)` looks up a **per-organization** webhook secret keyed by that owner name: [3](#0-2) 

The HMAC check (`GitHubApp#verify_webhook_signature`) is only a check that "this raw body was signed with *this org's* secret": [4](#0-3) 

Crucially, the signature check verifies the *whole raw payload was signed by org X's secret*; it does not independently constrain which `full_name` field is legitimate for org X to send. If Shipit is configured with an installation for organization `evil-org` (a legitimate, attacker-controlled GitHub App/organization onboarded to this Shipit instance with its own known/leaked webhook secret, or simply an org whose webhook the attacker can trigger by pushing to their own repo), the attacker can send a request with `X-Github-Event: push`, HMAC-signed using `evil-org`'s webhook secret, but with the JSON body's `repository.full_name` set to `"victim-org/victim-repo"` while `repository.owner.login` is left as `"evil-org"` (so signature verification succeeds against `evil-org`'s secret) — or, if `organization.login` is the field checked, still `evil-org`.

Every handler that acts on the payload derives its target strictly from `repository.full_name`, never re-checking it against `repository.owner.login`/`organization.login` used for signature selection: [5](#0-4) [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` blindly splits `full_name` and does a DB lookup with no relation to the org that authenticated: [8](#0-7) 

So the binding that should hold — "organization that authenticated == repository that is written" — is broken: the signature only proves *an* org's secret matched, not that the `full_name` in the body belongs to that org.

### Impact Explanation
Concretely, `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for any stack matching `victim-org/victim-repo` + branch, using an attacker-forged `after` SHA — this can desynchronize the tracked commit state / trigger `GithubSyncJob` for a repository the attacker doesn't own, using only credentials Shipit issued to an unrelated organization. The `pull_request` handlers go further: `OpenedHandler`/`ReopenedHandler`/`ClosedHandler`/`LabelCapturingHandler` create, archive, unarchive, or provision **review stacks** for `victim-org/victim-repo`, and `capture_labels` writes arbitrary `params.pull_request.labels` content onto real records, all keyed off `Shipit::Repository.from_github_repo_name(params.repository.full_name)`. Since none of this requires GitHub write access to the victim repo, actual `webhook_secret`s of the victim org, or a Shipit session, an attacker with only their own onboarded organization's credentials can write/mutate state belonging to a different repository Shipit tracks — a cross-repository write.

### Likelihood Explanation
This requires the attacker to control (or have leaked) the webhook secret for *some* organization already configured in this Shipit instance's `secrets.github` (i.e., an attacker who already has one legitimate, low-privilege org onboarded — e.g., is a member/admin of a smaller org sharing the same multi-tenant Shipit deployment, or has obtained one org's webhook secret through normal, non-privileged access). Given multi-org Shipit deployments (`github_app_config` per organization) are an explicit supported configuration, this is a realistic scenario, though it does require prior possession of one org's webhook secret — not the target's.

### Recommendation
After signature verification, validate that `params.dig('repository', 'full_name')` (and any repo/org identifiers subsequently used by handlers) actually belongs to the same organization login used to select the verifying secret (`repository_owner`) before dispatching to handlers, rejecting mismatched payloads.

### Proof of Concept
1. Shipit is configured with two organizations under `secrets.github`: `evil-org` (attacker-controlled, webhook secret known to attacker) and `victim-org` (tracked stacks/review-stacks exist for `victim-org/victim-repo`).
2. Attacker crafts a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": {
       "full_name": "victim-org/victim-repo",
       "owner": { "login": "evil-org" }
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(evil-org's webhook secret, body)` and POSTs to `/github/webhooks`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "evil-org")` and the signature validates successfully.
5. `PushHandler#process` runs `Repository.from_github_repo_name("victim-org/victim-repo")`, finds real stacks, and invokes `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` — mutating state for a repository the attacker's org has no relationship to, using only `evil-org`'s legitimate webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
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
    end
  end
end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
