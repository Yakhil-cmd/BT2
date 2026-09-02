### Title
Webhook signature verification uses an attacker-supplied `repository.owner.login` field to select the GitHub App/secret, decoupled from the `repository.full_name` field that is actually acted upon — allowing forged status/push events on repositories protected by a different app - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate the incoming signature against, based on `repository_owner`, a value read straight out of the *unverified* JSON body (`params.dig('repository','owner','login')`). The event is then dispatched to handlers that resolve the target `Stack`/`Repository` using a *different* field of that same unverified body, `repository.full_name`. Because these two fields are never cross-checked, and because `verify_webhook_signature` treats a blank/unset `webhook_secret` as automatically valid (`return true unless webhook_secret`), an attacker who knows of (or guesses) one configured organization whose app has no `webhook_secret` set can forge a webhook whose `repository.owner.login` points at that unsecured org while `repository.full_name` points at an entirely different, secured repository/stack tracked by Shipit. This is structurally the same class of bug as the audited CCTP issue: the field that is authenticated (`repository.owner.login` → org/app selected for signature check) is not the field that is acted upon (`repository.full_name` → which repository/stack gets mutated).

### Finding Description [1](#0-0)  shows `verify_signature` deriving `repository_owner` from the raw, not-yet-verified request body and using it to pick a `GithubApp` instance (`Shipit.github(organization: repository_owner)`), whose `webhook_secret` is then used to validate `X-Hub-Signature`. [2](#0-1)  shows that `verify_webhook_signature` short-circuits to `true` when `webhook_secret` is blank — i.e., for any configured organization without an explicit `webhook_secret`, signature verification is a no-op regardless of the actual `X-Hub-Signature` header contents.

Multi-organization deployments are an explicitly supported and documented configuration (`Shipit.github(organization:)`, `github_app_config`) as seen in [3](#0-2) , and the fixture/dummy config `secrets_double_github_app.yml` shows `webhook_secret:` left blank as a valid example configuration for an org entry.

Once signature "verification" passes (or is a no-op), `WebhooksController#create` dispatches the entire raw JSON body to handlers: [4](#0-3) . Handlers resolve the target repository from a **different** field of the same payload — `repository.full_name` — via `Shipit::Webhooks::Handlers::Handler#stacks`/`#repository_name`: [5](#0-4) . Nothing ties `repository.full_name` back to the organization (`repository.owner.login`) whose app/secret was used for signature verification.

This lets an attacker craft a payload where:
- `repository.owner.login` = `"OrgWithNoWebhookSecret"` (so signature check auto-passes)
- `repository.full_name` = `"victim-org/victim-repo"` (an actual tracked repository under a different, properly-secured org)

The push and status handlers then act on the victim repository/stack based purely on this forged, unauthenticated payload. For example, the status handler creates a `CommitStatus` for the named commit: [6](#0-5) . If that stack has `continuous_deployment: true`, a forged `state: success` status directly triggers an automatic deploy via `Commit`'s status callback and `ContinuousDeliveryJob`, as demonstrated in [7](#0-6) .

### Impact Explanation
This breaks the equality that should hold: `organization whose signature was verified == organization/repository the event is applied to`. An unprivileged attacker who can identify (or brute-force) any organization configured in the multi-org GitHub App setup without a `webhook_secret` can forge webhook deliveries that mutate state (commit statuses, sync jobs) for any *other* tracked repository/stack, including triggering an **unauthorized deploy** on stacks with `continuous_deployment: true`. This matches the "High/Critical — unauthorized deploy" impact bucket defined in scope.

### Likelihood Explanation
Requires: (1) the host operating Shipit with the multi-organization GitHub App configuration schema (a supported, documented mode — not a misconfiguration outside the engine's own design, as evidenced by the shipped `secrets_double_github_app.yml` fixture demonstrating `webhook_secret:` intentionally left blank), and (2) at least one configured organization lacking `webhook_secret`. Given that `webhook_secret` is optional per `GitHubApp#initialize` (`@webhook_secret = @config[:webhook_secret].presence`) and the code path silently treats its absence as "always verified," any operator who forgets/omits a secret for a low-priority or newly added organization inadvertently opens forgeable webhook access to every repository tracked in the same Shipit instance, not just that organization's repos. No authentication, token, or repository write access is required — only knowledge that such an org exists in the deployment's config and the target repo's `full_name`.

### Recommendation
Bind the two fields together: after resolving the target repository via `repository.full_name`, verify that its owning `Repository`/organization matches the `repository_owner`/app whose secret validated the signature (or, conversely, look up the webhook secret using the resolved target repository's organization, not an attacker-supplied field taken before verification). Additionally, treat a missing/blank `webhook_secret` for a configured organization as a hard failure (reject with 422) rather than an automatic pass, at minimum logging/alerting when an org is configured without a secret.

### Proof of Concept
1. Configure Shipit with two organizations: `OrgA` (has a `webhook_secret`) and `OrgB` (no `webhook_secret` set) — a supported configuration per `secrets_double_github_app.yml`.
2. Track a repository/stack `OrgA/critical-service` with `continuous_deployment: true`.
3. Send a forged `status` webhook to `POST /github/webhooks`:
   - Header: `X-Github-Event: status` (no valid `X-Hub-Signature` needed)
   - Body:
     ```json
     {
       "repository": { "owner": { "login": "OrgB" }, "full_name": "OrgA/critical-service" },
       "sha": "<head-sha-of-critical-service>",
       "state": "success",
       "branches": [{"name": "master"}],
       "context": "ci/travis"
     }
     ```
4. `verify_signature` resolves `Shipit.github(organization: "OrgB")`; since `OrgB` has no `webhook_secret`, `verify_webhook_signature` returns `true` unconditionally, regardless of signature header.
5. The status handler processes the payload using `repository.full_name = "OrgA/critical-service"`, creates a successful `CommitStatus` on that commit, and — because the stack has `continuous_deployment: true` — a `Deploy` is enqueued/triggered without any legitimate CI signal or GitHub-signed webhook for `OrgA`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
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

**File:** test/models/commits_test.rb (L233-243)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
        ContinuousDeliveryJob.new.perform(@stack)
      end
    end
```
