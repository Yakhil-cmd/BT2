### Title
Webhook signature is validated against the payload's `repository.owner.login`/`organization.login`, but events are applied to the repository named in `repository.full_name` - allowing a legitimately-onboarded GitHub organization to forge signed events for any other tracked repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret to validate an inbound webhook's HMAC against using one field of the attacker-controlled JSON body (`repository.owner.login`, falling back to `organization.login`), while the event dispatch logic that actually mutates state (`Shipit::Webhooks::Handlers::Handler#repository_name`) resolves the target `Repository`/`Stack` from a *different* field of the same body (`repository.full_name`). These two fields are never required to be consistent, so the equality "organization whose secret authenticated the request == owner of the repository the request writes to" is not enforced.

### Finding Description
The controller picks the signing organization purely from body content: [1](#0-0) [2](#0-1) 

Verification itself is a straight HMAC check over the raw body using whichever org's secret was selected: [3](#0-2) 

Once verified, `create` dispatches the same parsed JSON to event handlers: [4](#0-3) 

But the base `Handler` resolves the target repository/stack from an entirely different JSON key, `repository.full_name`, with no cross-check against the organization used to select the signing secret: [5](#0-4) 

In a genuine GitHub-originated webhook these two fields always agree (they are derived from the same repository object by GitHub), so this gap is invisible under normal operation. But Shipit supports multiple independently-configured GitHub organizations, each with its own `webhook_secret`: [6](#0-5) [7](#0-6) 

Because the webhook payload is an arbitrary JSON body that the sender fully controls (it is only checked via HMAC, not schema/consistency validated), an entity that legitimately possesses the webhook secret for **their own** onboarded organization ("OrgA") can construct a payload where `repository.owner.login` = `"OrgA"` (so `verify_signature` passes using OrgA's own secret) but `repository.full_name` = `"OrgB/victim-repo"` (a completely different organization tracked by the same Shipit instance). The request passes signature verification and is then processed as if it legitimately targeted OrgB's repository.

### Impact Explanation
This breaks the binding "organization that authenticated == repository that is written," letting a party trusted only for OrgA forge state-changing webhook events against OrgB's stacks:
- The `push` handler enqueues `GithubSyncJob` against OrgB's stack with an attacker-chosen `after` sha, as exercised by `:push with the target branch queues a GithubSyncJob` — forged for a foreign repo.
- The `status` handler creates a `Status` record with attacker-chosen `state`/`context`/`target_url` for an arbitrary commit sha in OrgB's repo, per the flow tested in `:state create a Status for the specific commit` — this can be used to fabricate passing/failing CI signals on commits Shipit uses to gate deploys.
- The `check_suite` handler enqueues `RefreshCheckRunsJob` against a foreign stack. [8](#0-7) 

Forging commit status/check state on a stack that determines mergeability/deployability is a cross-organization write into state that Shipit uses for deploy decisions, matching the "cross-repository writes" / "unauthorized deploy" impact category.

### Likelihood Explanation
Exploitation requires only credentials the attacker legitimately controls — the webhook secret of their own onboarded GitHub organization — not any secret belonging to the victim organization, the victim's `ApiClient` token, or a Shipit session. This is only reachable on installations configured with multiple GitHub organizations (the `secrets.github` multi-org schema), which the engine explicitly documents and supports.

### Recommendation
When resolving the organization for a webhook, require that the organization used to select the signing secret (`repository.owner.login`/`organization.login`) matches the organization portion of `repository.full_name` used by `Handler#repository_name` before dispatching to a handler; reject the request (422) on mismatch.

### Proof of Concept
1. Shipit is configured with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `config/secrets.development.shopify.yml`).
2. An entity holding `OrgA`'s legitimate webhook secret crafts a `status` event JSON body: `{"repository": {"owner": {"login": "OrgA"}, "full_name": "OrgB/victim-repo"}, "sha": "<victim-commit>", "state": "success", ...}`.
3. It signs the raw body with `OrgA`'s secret and sends it with `X-Github-Event: status`; `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgA")` and the HMAC check passes.
4. `Shipit::Webhooks.for_event('status').each { |handler| handler.call(params) }` runs; the status handler resolves the target repo via `payload.dig('repository','full_name')` = `"OrgB/victim-repo"` and writes a forged `Status` onto `OrgB`'s tracked commit, despite the request never being signed by `OrgB`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```

**File:** test/controllers/webhooks_controller_test.rb (L23-59)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
    end

    test ":push does not enqueue a job if not the target branch" do
      request.headers['X-Github-Event'] = 'push'
      params = JSON.parse(payload(:push_not_master)).to_json
      assert_no_enqueued_jobs do
        post :create, body: params, as: :json
      end
    end

    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
