### Title
Webhook signature is verified against the organization named in the payload while the affected repository is looked up from a separate, uncross-checked payload field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate an inbound webhook's HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the still-unauthenticated JSON body. [1](#0-0) [2](#0-1) 

Once the signature check passes, the *entire* parsed body is dispatched unmodified to every registered handler for the event type: [3](#0-2) 

Handlers never re-derive the "organization" that was used for signature selection. Instead they resolve the actual `Repository`/`Stack` to mutate using an independent field, `repository.full_name`: [4](#0-3) [5](#0-4) [6](#0-5) 

### Finding Description
Shipit explicitly supports hosting multiple GitHub organizations from a single instance, each with its own `webhook_secret`, looked up via `Shipit.github(organization:)`: [7](#0-6) [8](#0-7) 

This creates the trust binding: `organization-that-cryptographically-authenticated == repository-that-is-mutated`. In practice these are two different, independently attacker-controlled JSON fields evaluated at two different stages:

1. `verify_signature` picks the HMAC key using `repository.owner.login` from the (not-yet-verified) body.
2. `verify_webhook_signature` only proves the request was signed with *that named organization's* secret.
3. Every `Handler` subclass then resolves the repository to act on via `repository.full_name` — a sibling field in the same JSON body that is never compared against the `owner.login` value used in step 1.

An attacker who legitimately installs their own GitHub App on an org they control (e.g. `AttackerOrg`, which Shipit is also configured to track) knows `AttackerOrg`'s real `webhook_secret` and can compute a valid `X-Hub-Signature` for any payload they like. They can then set:
```json
{
  "repository": { "owner": { "login": "AttackerOrg" }, "full_name": "victim-org/victim-repo" },
  ...
}
```
`verify_signature` selects and validates against `AttackerOrg`'s secret (succeeds, since the attacker signed it), but `repository_name` used by every handler resolves to `victim-org/victim-repo`, which the attacker does not control and never proved knowledge of any secret for.

This is the same class of bug as the STON.fi report: a value the signer/authenticator is bound to (`repository.owner.login`, analogous to the swap's `to_address`) diverges from the value the state-mutating operation actually acts on (`repository.full_name`, analogous to `lp_account`'s owner), because the intermediary (the router contract / `WebhooksController`) forwards attacker-supplied data as if it were validated identity.

### Impact Explanation
Handlers reachable this way perform real state changes on stacks/repositories the attacker does not own or have signature capability for:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for any branch/stack under the spoofed repo. [9](#0-8) 
- `PullRequest::OpenedHandler`/`ClosedHandler`/`ReopenedHandler`/`LabeledHandler` create, archive, or unarchive review stacks for the victim repository. [10](#0-9) 
- The `status` event path creates a `Status` on the victim's commit, which can flip commit deployability and, combined with `continuous_deployment` being enabled on the victim stack, trigger an unauthorized deploy via `schedule_continuous_delivery` → `trigger_continuous_delivery` → `trigger_deploy`. [11](#0-10) [12](#0-11) 

This is a cross-repository/cross-organization write and can lead to an unauthorized deploy on a stack the attacker has no legitimate access to — matching the "Critical: cross-repository writes, or an unauthorized deploy" bar.

### Likelihood Explanation
Exploitability requires only that the attacker control a GitHub App installation on some organization that this Shipit instance also tracks in its multi-org `github:` config (a normal, low-privilege, self-service action — installing your own GitHub App is not a Shipit credential and not the victim's secret). No Shipit session, `ApiClient` token, or victim webhook secret is needed. The only non-trivial part is that the deployment must use the multi-organization secrets schema (`Shipit.github(organization: ...)` with multiple orgs configured), which is a documented, supported configuration.

### Recommendation
- After verifying the HMAC signature, re-validate that `repository.full_name`'s owner segment matches the `organization` whose secret validated the signature (or better, derive the organization strictly from `repository.full_name` and require exactly one canonical field to be used for both signature-key selection and repository resolution).
- Alternatively, have `Handler#repository_name`/`stacks` receive the already-authenticated organization as an explicit argument from `WebhooksController`, and reject/ignore events whose `repository.full_name` owner does not match it.

### Proof of Concept
1. Configure Shipit with two GitHub Apps/orgs, `AttackerOrg` and `victim-org`, each installed and tracked (per `docs/setup.md`'s "Using Multiple GitHub Applications" section).
2. Attacker installs and controls a GitHub App on `AttackerOrg`, obtaining `AttackerOrg`'s `webhook_secret`.
3. Attacker crafts a `push` (or `pull_request`/`status`) webhook JSON body with `repository.owner.login = "AttackerOrg"` and `repository.full_name = "victim-org/victim-repo"`, computes `X-Hub-Signature: sha1=HMAC(AttackerOrg_secret, body)`, and POSTs it to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "AttackerOrg")` and successfully verifies the signature. [1](#0-0) 
5. `PushHandler#process` resolves stacks via `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github` on the victim's real stack, with no proof the attacker ever had `victim-org`'s webhook secret. [4](#0-3) [9](#0-8)

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-50)
```ruby
          def find_or_create!
            stack || create!
          end

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

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```
