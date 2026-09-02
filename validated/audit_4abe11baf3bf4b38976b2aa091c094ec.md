### Title
Webhook signature is verified against the organization named in the payload, but handlers act on unrelated repository/commit data in the same payload — allowing cross-repository status/stack forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on a field taken from the **same untrusted JSON body** it is about to verify (`repository.owner.login` or `organization.login`). Once the signature is confirmed valid for *that* organization, the full, attacker-controlled JSON body is handed to event handlers that key their side effects off *different* fields of the same payload (`repository.full_name`, or, in the `status` handler, a completely unscoped `sha`). Nothing binds "the organization whose secret validated this request" to "the repository/commit that the handler is about to mutate." An attacker who legitimately controls (and knows the `webhook_secret` for) one organization configured on the Shipit instance can therefore forge signed webhook deliveries that write to stacks/commits belonging to any other organization/repository hosted on the same Shipit instance.

### Finding Description
`verify_signature` picks the `GitHub App`/secret purely from payload content: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of `params` (the parsed request body) before any authenticity check has occurred, and is used only to select which configured organization's `webhook_secret` is used to compute the expected HMAC: [3](#0-2) [4](#0-3) 

In a multi-organization deployment (`docs/setup.md` "Using Multiple GitHub Applications"), each organization has its own `webhook_secret`, and that secret is chosen by whoever creates the GitHub App for that organization — i.e. an org admin who onboards their own organization onto the shared Shipit instance legitimately knows their own org's `webhook_secret`.

After the signature check passes, the entire body is dispatched to handlers, unconstrained by the organization used above: [5](#0-4) 

Handlers scope their side effects using `repository.full_name` from the payload — a field never checked against the organization that authenticated the request: [6](#0-5) [7](#0-6) 

The `status` handler is worse: it doesn't even use `repository` — it matches purely on commit `sha` across the whole database: [8](#0-7) 

So the equality that should hold — `organization used to select/verify webhook_secret == organization/repository whose data the handler mutates` — is never enforced. The signature only proves "this body was HMAC'd with organization X's secret"; it proves nothing about which repository/commit inside the body the handler is permitted to touch.

### Impact Explanation
An attacker who controls one organization onboarded to a shared/multi-tenant Shipit instance (and therefore knows that organization's `webhook_secret`) can craft an arbitrary JSON body, set `repository.owner.login`/`organization.login` to their own org (so `verify_signature` picks their own known secret and the HMAC passes), but set `repository.full_name` (or, for `status` events, `sha`) to reference a victim organization's repository/commit. This lets the attacker:
- Forge `push` events to trigger `stack.sync_github(expected_head_sha: ...)` on a victim's stacks [9](#0-8) 
- Forge `pull_request` events to archive/unarchive victim review stacks or overwrite victim `PullRequest` records [10](#0-9) 
- Forge `status` events to inject arbitrary commit statuses on any commit in the system by `sha` alone, potentially manipulating CI-gated deploy eligibility for unrelated stacks [8](#0-7) 

This is a cross-repository/cross-organization write achieved without any credential belonging to the victim organization — satisfying the "cross-repository writes" Critical impact bar.

### Likelihood Explanation
Requires the attacker to be an onboarding organization admin (or otherwise know one configured `webhook_secret`) on a Shipit instance that hosts multiple organizations/repositories — this is an explicitly documented, supported configuration (`docs/setup.md`, "Using Multiple Github Applications"). No repository write access, `ApiClient` token, or session on the victim's side is needed; only knowledge of one legitimate, self-configured `webhook_secret`.

### Recommendation
Bind the verified organization to the data being mutated: after computing `repository_owner`/`organization` used for signature verification, re-derive the same value from `repository.full_name` (or the resource actually acted upon) and reject the webhook if they don't match the organization whose secret validated the signature. For `status_handler.rb`, scope `Commit.where(sha:)` lookups to commits belonging to repositories under the verified organization rather than searching globally by `sha`.

### Proof of Concept
1. Attacker owns/administers `evil-org`, which is configured in Shipit's multi-org `secrets.yml` with `webhook_secret = S` (known to the attacker because they set it up).
2. Attacker crafts a `push` webhook body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": { "owner": { "login": "evil-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"evil-org"` from the body, fetches `evil-org`'s `GitHubApp`, and `verify_webhook_signature` succeeds because the attacker signed with the correct (their own) secret.
5. `Shipit::Webhooks::Handlers::PushHandler.call(params)` runs, resolving stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` — a repository belonging to a different organization than the one whose secret authenticated the request — and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the victim's stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
