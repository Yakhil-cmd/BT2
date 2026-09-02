I have enough evidence to substantiate the analog finding. Here's the analysis:

### Title
Webhook signature is verified against the payload's `repository.owner.login` organization while every event handler acts on the payload's `repository.full_name` field, allowing a valid signature from one GitHub organization to authorize actions against a repository owned by a different organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (with a fallback to `organization.login`) [1](#0-0) , [2](#0-1) . Once verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the *entire raw JSON body* — not just the verified owner field — to the handlers [3](#0-2) . Every handler resolves the target repository/stack from a completely different field, `repository.full_name`, via `Shipit::Repository.from_github_repo_name` [4](#0-3) [5](#0-4) [6](#0-5) .

### Finding Description
This is structurally the same bug class as the RCTreasury report: two computations that are supposed to represent the same point-in-time state instead use two different, independently-controllable inputs, and the code silently assumes they agree. Here, the equality that must hold is:

`organization that authenticated the request == owner of the repository the handler writes to`

Concretely:
- Shipit supports multi-org configuration where each GitHub organization has its own independent `webhook_secret`, as documented and exercised in `test/dummy/config/secrets_double_github_app.yml` and `docs/setup.md`.
- `verify_signature` looks up the app/secret via `Shipit.github(organization: repository_owner)` where `repository_owner` reads `repository.owner.login` straight out of the attacker-suppliable JSON body [7](#0-6) [2](#0-1) .
- The HMAC (`verify_webhook_signature`) only proves the raw body was signed with *that organization's* secret — it proves nothing about which repository the payload's handlers will actually touch [8](#0-7) .
- All handlers (`PushHandler`, `PullRequest::OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`, etc.) instead key off `repository.full_name` to resolve the `Repository`/`Stack` to act on [9](#0-8) [10](#0-9) .
- Nothing ties `repository.owner.login` to `repository.full_name`'s owner segment before the handler is invoked. An attacker who legitimately possesses (or is given) the `webhook_secret` for one org registered on the same Shipit instance can freely set `repository.owner.login` to that org (so signing checks out) while setting `repository.full_name` to `"OtherOrg/other-repo"` for a completely different, unrelated organization also configured on that instance.

### Impact Explanation
Because `PullRequest::OpenedHandler`/`ReviewStackAdapter` derive the branch to build from attacker-controlled `pull_request.head.ref` and only gate on the *target* repository's `review_stacks_enabled`/`provisioning_behavior` flags (fields belonging to `OtherOrg/other-repo`, not the authenticating org) [11](#0-10) [12](#0-11) , a forged `pull_request` event can queue a new `ReviewStack` for `OtherOrg/other-repo` for provisioning via `ReviewStackProvisioningQueue.add(stack)` [13](#0-12) , which is later provisioned/deployed by `ReviewStackProvisioningQueue#work` [14](#0-13) . This is a cross-repository/cross-organization unauthorized deploy triggered using only a webhook secret belonging to an unrelated, lower-trust organization — matching the Critical impact bar ("cross-repository writes, or an unauthorized deploy").

### Likelihood Explanation
Any Shipit deployment configured with more than one GitHub organization (a documented, first-class configuration, see `docs/setup.md` "Using Multiple Github Applications") is affected. Anyone who administers the GitHub App/webhook settings for the weakest of the configured organizations (i.e., who knows that org's `webhook_secret`) can send an arbitrary raw HTTP POST directly to the public `/webhooks` endpoint — no GitHub involvement, no privileged Shipit account, and no `ApiClient` token needed — because the controller only checks the HMAC, not that the signed org matches the acted-upon repository.

### Recommendation
After signature verification succeeds, re-derive the repository/organization strictly from the same trusted value used to select the signing secret, and reject the payload if `repository.full_name`'s owner segment does not match the `repository_owner` used in `verify_signature`. Alternatively, have `Handler#repository_name`/`Repository.from_github_repo_name` scope lookups by the verified organization rather than trusting the payload's `repository.full_name` independently.

### Proof of Concept
1. Configure Shipit with two organizations, `LowTrustOrg` and `HighValueOrg`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As an actor who knows `LowTrustOrg`'s `webhook_secret` (e.g. an org owner who configured that org's GitHub App webhook), craft a JSON body:
```json
{
  "action": "opened",
  "number": 1,
  "repository": { "owner": { "login": "LowTrustOrg" }, "full_name": "HighValueOrg/critical-repo" },
  "pull_request": { "head": { "ref": "attacker-branch" }, ... },
  "sender": { "login": "attacker" }
}
```
3. Sign it with `OpenSSL::HMAC.hexdigest('sha1', LowTrustOrg_webhook_secret, body)` and send it as `X-Hub-Signature` with `X-Github-Event: pull_request` to `POST /webhooks` (per `WebhooksController#verify_signature`, `app/controllers/shipit/webhooks_controller.rb`).
4. `verify_signature` succeeds because it only checks `LowTrustOrg`'s secret against the raw body.
5. `Webhooks::Handlers::PullRequest::OpenedHandler` resolves `Shipit::Repository.from_github_repo_name("HighValueOrg/critical-repo")` [5](#0-4) , and if that repo has `review_stacks_enabled`/`allow_all`, it creates and enqueues a `ReviewStack` on the attacker-chosen branch for provisioning — a cross-organization unauthorized deploy triggered without any credential belonging to `HighValueOrg`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-70)
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

          def pull_request
            params.pull_request
          end

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L64-66)
```ruby
          def repo_name
            params.repository["full_name"]
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-98)
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

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end

          def environment
            "pr#{params.number}"
          end
```

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L17-37)
```ruby
    def work
      queued_stacks.find_each(&method(:provision))
    end

    def queued_stacks
      @queued_stacks ||= Shipit::ReviewStack
                         .with_provision_status(:deprovisioned)
                         .where(awaiting_provision: true)
    end

    private

    def provision(stack)
      if stack.provisioner.provision?
        stack.provision
      else
        Rails.logger.info(
          "Putting review ReviewStack<#{stack.id}> back into the provisioning queue - #provision? was falsey."
        )
      end
    end
```
