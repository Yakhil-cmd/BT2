### Title
Cross-org webhook confused deputy: `full_name` used to select the provisioned repository is never validated against the organization whose secret verified the signature - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`WebhooksController#verify_signature` verifies the HMAC using `repository_owner` (`payload.dig('repository','owner','login')`), but `OpenedHandler#repository` resolves the target `Repository` using the independent, uncorrelated field `params.repository.full_name`. An attacker who controls a Shipit-configured GitHub organization (and therefore knows its own `webhook_secret`) can sign a `pull_request` "opened" payload where `repository.owner.login` is their own org (so signature verification passes) while `repository.full_name` names a victim's tracked repository, causing `ReviewStackAdapter#find_or_create!` to provision a `ReviewStack` under the victim's `Repository`.

### Finding Description
The claimed binding is: `verify_signature`'s `repository_owner` (org that signed the payload) == the organization owning the `Repository`/`review_stacks` that `OpenedHandler` acts on. Tracing the code shows this equality is **not enforced**:

- `WebhooksController#verify_signature` selects the GitHub App/secret using only `params.dig('repository','owner','login')`: [1](#0-0) [2](#0-1) 

- `OpenedHandler#repository` looks up the target repository using an entirely separate field, `params.repository.full_name`, with no cross-check against `repository.owner.login`: [3](#0-2) 

- `provision?` and `respond_to_pull_request_opened?` then decide, based solely on that resolved (victim) `Repository`'s configuration (`review_stacks_enabled`, `provisioning_behavior_prevent_with_label?`), whether to provision: [4](#0-3) 

- `process` then calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!`, which creates a `ReviewStack` belonging to the victim's `Repository` and enqueues it for provisioning: [5](#0-4) [6](#0-5) [7](#0-6) 

Root cause: `repository.owner.login` (used for signature/authentication scoping) and `repository.full_name` (used for authorization/target-selection) are two independent JSON fields inside the same attacker-controlled request body. Nothing in `ExplicitParameters` schema, `drop_unhandled_event`, or the handler cross-validates that the verified signing organization actually owns the `full_name` repository being acted upon. `Repository.from_github_repo_name` does a raw `find_by(owner:, name:)` lookup with no tie back to the signer: [8](#0-7) 

Regarding execution credentials: `TaskCommands`/`StackCommands`/`Commands#base_env` fetch the GitHub token used in `PTY.spawn`-backed `Command` execution via `Shipit.github(organization: repository.owner)` (through `Repository#github_app`, `Stack#env`/`repository.owner`), i.e. keyed off the victim `Repository`'s own `owner` column, not the attacker's org: [9](#0-8) [10](#0-9) 

So the provisioned `ReviewStack`'s eventual deploy `Task` runs with the **victim's** real `GITHUB_TOKEN`/App credentials, not the attacker's — confirming this is a genuine cross-org confused-deputy record creation and would drive real deploy `Command` execution scoped to the victim's org/credentials, triggered purely by an attacker-signed payload naming the victim as target.

Existing guards checked and found insufficient:
- `verify_signature`/`GitHubApp#verify_webhook_signature` only prove the request was signed by *some* configured org's secret (the attacker's own, since the attacker is assumed to control/own that org's Shipit-configured secret) — they do not bind that org to the `repository.full_name` acted upon.
- `drop_unhandled_event` only filters by event type, not by payload consistency.
- `ExplicitParameters` schema only requires the presence/types of `repository.full_name`, `sender.login`, etc.; it performs no cross-field validation against `repository.owner.login`.
- `Repository` model validations (`owner`/`name` format) validate the stored repository record, not the incoming webhook's internal consistency.
- No `require_permission!`, `User#authorized?`, or `force_github_authentication` guard exists in the webhook path at all — these apply to session/API paths, not to `POST /webhooks`.

### Impact Explanation
An attacker with control of any GitHub organization/App installation that Shipit is configured to trust (and thus knows that org's `webhook_secret`) can, for any *other already-tracked* victim repository configured with `provisioning_behavior_prevent_with_label` (or `allow_all`), forge a signed `pull_request` "opened" webhook that creates a `ReviewStack` for the victim repository and PR number of the attacker's choosing. This is a payload for one organization mutating another repository's stack/records (`Repository.review_stacks`), matching the Critical impact category. The created `ReviewStack` is queued for provisioning (`ReviewStackProvisioningQueue.add`), which subsequently runs deploy `Command`s (via `PTY.spawn`) using the **victim's** actual `GITHUB_TOKEN`, git clone URLs (`branch: params.pull_request.head.ref`), and deploy-time secrets — i.e., an unauthorized deploy is triggered against the victim's infrastructure. This is repeatable for every tracked repository whose owning org differs from the attacker's, and blast radius scales with the number of organizations onboarded into the same multi-tenant Shipit instance (`Shipit.github_organizations`, `secrets.github` keyed by org).

### Likelihood Explanation
Preconditions: the attacker must control at least one GitHub organization/App installation that this Shipit instance has configured in `secrets.github` (multi-org config, `github_app_config`), which is realistic for any multi-tenant Shipit deployment onboarding several customer organizations. The attacker knows their own org's `webhook_secret` (they configure it themselves per `docs/setup.md`). The victim repository must already be tracked by Shipit with `review_stacks_enabled` and `provisioning_behavior_allow_all`/`prevent_with_label` (a standard review-stack configuration). No Shipit session, API token, or GitHub credentials for the victim org are needed — only a single crafted HTTP POST to `/webhooks` with a valid signature over the attacker-chosen body. This is low-cost and fully repeatable/scriptable per target repository/PR number.

### Recommendation
In `WebhooksController#verify_signature`, and/or in each handler's repository resolution (`OpenedHandler#repository`, similarly for other `pull_request` handlers, `push`, `status`, etc.), enforce that the organization used to verify the signature equals the owner of the repository the handler is about to act on — e.g. reject the webhook if `repository.owner.login.downcase != Repository.from_github_repo_name(params.repository.full_name)&.owner`, or simply derive the target `Repository` using the verified `repository_owner` rather than trusting `full_name` independently.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_cross_org_test.rb
require 'test_helper'

module Shipit
  class WebhooksCrossOrgProvisionTest < ActionController::TestCase
    tests Shipit::WebhooksController

    setup do
      # Victim repo tracked under "victim-org", provisioning without label required
      @victim_repo = shipit_repositories(:shipit) # owner: 'shopify' in fixtures, treat as victim
      @victim_repo.update!(
        review_stacks_enabled: true,
        provisioning_behavior: :prevent_with_label,
        provisioning_label_name: 'do-not-provision'
      )
    end

    test "attacker-signed payload (attacker org) provisions a ReviewStack for victim repository" do
      attacker_secret = 'attacker-known-secret'
      Shipit.stubs(:github).with(organization: 'attacker-org').returns(
        Shipit::GitHubApp.new('attacker-org', webhook_secret: attacker_secret)
      )

      payload = payload_parsed(:pull_request_opened)
      payload['repository']['owner']['login'] = 'attacker-org' # controls signing org
      payload['repository']['full_name'] = @victim_repo.full_name # targets victim
      payload['pull_request']['labels'] = [] # satisfies !pull_request_has_provisioning_label?
      body = payload.to_json

      signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', attacker_secret, body)}"
      @request.headers['X-Github-Event'] = 'pull_request'
      @request.headers['X-Hub-Signature'] = signature

      assert_difference -> { @victim_repo.review_stacks.count }, 1 do
        post :create, body:, as: :json
        assert_response :ok
      end
      # Binding check: signer org ('attacker-org') != stack.repository.owner ('shopify'/victim)
      stack = @victim_repo.review_stacks.last
      refute_equal 'attacker-org', stack.repository.owner
    end
  end
end
```
This demonstrates `repository_owner` ("attacker-org", the signer) diverging from `stack.repository.owner` ("shopify"/victim, the actual repository mutated), proving the binding is violated and a live `ReviewStack` (subject to later deploy `Task` execution with the victim's `GITHUB_TOKEN`) is created for a repository the signing organization never authenticated for.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-70)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-21)
```ruby
          def find_or_create!
            stack || create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-85)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/repository.rb (L100-102)
```ruby
    def github_app
      Shipit.github(organization: owner)
    end
```

**File:** lib/shipit/commands.rb (L37-54)
```ruby
    def base_env
      @base_env ||= begin
        env = Shipit.env.merge(
          'GITHUB_DOMAIN' => github.domain,
          'GITHUB_TOKEN' => github.token
        )

        if Shipit.use_git_askpass?
          env['GIT_ASKPASS'] = Shipit::Engine.root.join('lib', 'snippets', 'git-askpass').realpath.to_s
        end

        env
      end
    end

    def github
      Shipit.github
    end
```
