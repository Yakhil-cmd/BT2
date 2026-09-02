### Title
Forged webhooks to a secret-less GitHub org authorize archive/unarchive of arbitrary review stacks via unrelated `repository.full_name` field - ([File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus whether an HMAC signature is required) using `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) , while `Handlers::Handler#stacks`/`repository_name` resolves the target `Repository` using the completely independent `payload.dig('repository','full_name')` field [3](#0-2) . When the org named in `repository.owner.login` is configured without a `webhook_secret`, `GitHubApp#verify_webhook_signature` unconditionally returns `true` for any payload [4](#0-3) , so an attacker can forge a webhook that "verifies" against a secret-less org while setting `repository.full_name` to any other tenant's repository, causing PR handlers to archive/unarchive that tenant's review stacks.

### Finding Description
Broken binding (stated as an equality that the code never enforces): `params.dig('repository','owner','login')` (used to pick the verifying `GitHubApp`) **should equal** the owner portion of `payload.dig('repository','full_name')` (used to resolve the target `Repository`/`Stack`). Nothing in `WebhooksController` or `Handlers::Handler` checks this.

Path:
1. `WebhooksController#create` runs `before_action :verify_signature` [5](#0-4) .
2. `verify_signature` calls `Shipit.github(organization: repository_owner)` where `repository_owner` reads `params.dig('repository','owner','login')` [1](#0-0) [2](#0-1) . This only requires the org name to be a *configured* org (`GithubOrganizationUnknown` raised otherwise) — org names are not secret.
3. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank [6](#0-5) , per `secrets.yml`'s documented "optional" webhook secret [7](#0-6) .
4. Once verification passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` is invoked with the raw, fully attacker-controlled JSON body [8](#0-7) .
5. For `pull_request` events (`labeled`/`unlabeled`/`closed`), the handlers resolve `repository = Shipit::Repository.from_github_repo_name(params.repository.full_name)` — a field entirely distinct from the one used in step 2 [9](#0-8) [10](#0-9) .
6. `LabeledHandler#handle` then calls `stack.archive!` or `stack.unarchive!` based on attacker-supplied labels and provisioning behavior read straight from the forged payload [11](#0-10) , and `ReviewStackAdapter#archive!`/`#unarchive!` perform real state mutation (`deprovision`, `archive!`, `unarchive!`) on the resolved review stack [12](#0-11) .

Why guards fail: `drop_unhandled_event` only checks the event type is handled, not payload authenticity [13](#0-12) . `verify_signature`'s only real security value exists when the resolved org has a non-blank `webhook_secret`; for secret-less orgs it is a no-op. Model validations on `Repository`/`Stack` do not tie a stack to a signing org, and `ExplicitParameters` schemas for the PR handlers require only presence/types of `repository.full_name`, not that it matches the verifying org [14](#0-13) .

Attacker request: `POST /webhooks` with header `X-Github-Event: pull_request` and JSON body where `repository.owner.login` = a Shipit-configured org that has `webhook_secret` unset (org names are public), and `repository.full_name` = `"victim-owner/victim-repo"` (any repo actually tracked by this Shipit instance), plus `action: "labeled"`, a provisioning label, and `sender.login` of the attacker's choosing.

### Impact Explanation
The attacker can archive or unarchive (deprovision/reprovision) any tenant's review stack tracked by the Shipit instance, without any relationship to the org that "verified" the webhook — this is exactly the "payload for one repository mutating another's stack" Critical category. Repeatable against every `Repository`/review stack in the instance's database, for any pull-request-driven state (`labeled`, `unlabeled`, `closed`→`archive!`). Blast radius spans all tenants sharing the Shipit instance, not merely stale/renamed repos as the original hypothesis suggested — the divergence works even with a perfectly fresh, correctly-owned `Repository` row, since `full_name` used for lookup is never checked against the signing org at all.

### Likelihood Explanation
Preconditions: at least one GitHub org configured in `secrets.yml`/`github` section without a `webhook_secret` (explicitly documented as optional, so plausible in real deployments, especially ones bootstrapped from `docs/setup.md`) [7](#0-6) ; multi-tenant install with other repos tracked. Attacker cost is trivial: no credentials, tokens, or secrets required — only the public org name and the target repo's `owner/name` string (visible in the Shipit UI/URL, since `to_param` returns `github_repo_name`) [15](#0-14) . Fully repeatable per request.

### Recommendation
Bind the signature-verifying identity to the resolved target: after resolving `Repository` (via `full_name`), require that its `owner` matches the `repository.owner.login`/`organization.login` used in `verify_signature`, and reject (422) on mismatch. Alternatively, always require a non-blank `webhook_secret` for every configured org (remove the "no-secret" fallback in `GitHubApp#verify_webhook_signature`), eliminating the trivial-forgery path entirely.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (extending existing suite):
```ruby
test "forged webhook for secret-less org archives an unrelated tenant's review stack" do
  # Arrange: org "secretless-org" configured with no webhook_secret (test dummy secrets already have webhook_secret: nil)
  victim_repo = shipit_repositories(:shipit)          # owner/name != "secretless-org"
  victim_stack = shipit_review_stacks(:review_stack)  # belongs to victim_repo, not archived
  assert_not victim_stack.archived?

  request.headers['X-Github-Event'] = 'pull_request'
  payload = {
    action: "labeled",
    number: victim_stack.pull_request.number,
    pull_request: { id: 1, number: victim_stack.pull_request.number, url: "u", title: "t",
                     state: "open", additions: 1, deletions: 1,
                     head: { sha: "abc", ref: "branch" }, user: { login: "attacker" },
                     assignees: [], labels: [{ name: Shipit.provisioning_label }] },
    label: { name: Shipit.provisioning_label },
    repository: {
      owner: { login: "secretless-org" },     # org used ONLY for signature bypass
      full_name: victim_repo.github_repo_name # unrelated victim repo used for lookup
    },
    sender: { login: "attacker" }
  }.to_json

  # Assert: equality check that SHOULD hold but doesn't:
  #   JSON.parse(payload).dig("repository","owner","login") == victim_repo.owner  -> false (mismatch)
  post :create, body: payload, as: :json

  assert_response :ok
  assert victim_stack.reload.archived?, "cross-tenant stack was mutated via a mismatched owner/full_name webhook"
end
```
This demonstrates the divergence: `repository.owner.login` ("secretless-org") never equals `victim_repo.owner`, yet the forged request still results in `victim_stack.archive!` being executed.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-16)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L31-39)
```ruby
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-50)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```

**File:** app/models/shipit/repository.rb (L86-88)
```ruby
    def to_param
      github_repo_name
    end
```
