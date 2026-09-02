This confirms the vulnerability chain end-to-end: the `StatusHandler` (`app/models/shipit/webhooks/handlers/status_handler.rb`) matches `Commit.where(sha: params.sha)` across the whole database (not scoped by repository at all) and calls `commit.create_status_from_github!`, which flows into `Status#schedule_continuous_delivery` → `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob`, triggering an actual unauthorized deploy when `stack.continuous_deployment?` is enabled, as shown in `test/models/commits_test.rb:233-243`.

### Title
Webhook signature verification is scoped to the wrong organization, allowing forged cross-repository events to trigger unauthorized deploys - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The `WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using the organization name found in the payload's `repository.owner.login`/`organization.login`, but the event handlers that actually act on the payload use `repository.full_name` (or, for the `status` event, no repository scoping at all) to decide what to mutate. In a multi-organization Shipit deployment, an attacker who administers one onboarded GitHub organization (and therefore legitimately knows that organization's `webhook_secret`) can forge a payload whose `repository.owner.login` names their own org (to pass signature verification) while its `repository.full_name`/`sha` target a different, unrelated repository/commit tracked by Shipit. The signature check never verifies that the org used for the HMAC matches the repository the handler will actually modify.

### Finding Description
`verify_signature` computes the verifying GitHub App from the payload-controlled owner field: [1](#0-0) [2](#0-1) 

Once verified, the controller dispatches the exact same JSON body to handlers without re-checking the organization: [3](#0-2) 

Most handlers resolve the target `Repository` from `repository.full_name` in the payload, independent of which organization's secret validated the signature: [4](#0-3) 

The `status` event handler is even weaker: it doesn't scope by repository at all, matching any commit in the entire database by SHA: [5](#0-4) 

Shipit explicitly supports multiple independently configured GitHub Apps/organizations, each with its own `webhook_secret`, as documented and exercised in tests: [6](#0-5) [7](#0-6) 

This breaks the intended binding: *organization whose secret authenticated the request* == *repository/commit the request is permitted to write to*. Nothing enforces that `Shipit.github(organization: repository_owner)` corresponds to the org owning the repository/commit the handler subsequently mutates.

### Impact Explanation
Creating a forged `status` (or `check_suite`/`check_run`) event for an arbitrary commit SHA lets the attacker set that commit's CI status to `success`. If the targeted stack has `continuous_deployment?` enabled, this directly triggers `ContinuousDeliveryJob` via `Commit#schedule_continuous_delivery`, resulting in an **unauthorized deploy** — an explicitly listed Critical impact. It can equally be used to forge `pull_request`/`push` events to manipulate review-stack provisioning/archival or enqueue `GithubSyncJob` against a repository the attacker does not control, all authenticated only by a webhook secret that belongs to a completely different organization. [8](#0-7) [9](#0-8) 

### Likelihood Explanation
Requires only that the Shipit instance be configured for multiple GitHub organizations (a documented, supported configuration) and that the attacker legitimately controls one of those onboarded organizations/GitHub Apps (thus knowing its own `webhook_secret`, which they configured themselves or which was issued to them for their own org). No access to the victim org, no `ApiClient` token, and no Shipit session is required — only the ability to send a POST to the public `/webhooks` endpoint.

### Recommendation
After verifying the HMAC, cross-check that the organization used to select the webhook secret actually matches the owner of the `repository.full_name` (and, for `status`/`check_suite` events, that the returned commits' stacks belong to a repository under that same verified organization) before processing the payload in any handler. Reject the webhook if these do not match.

### Proof of Concept
1. Configure Shipit for two orgs, `attacker-org` and `victim-org`, each with distinct `webhook_secret`s (supported multi-org config, `docs/setup.md:182-209`).
2. Attacker legitimately knows `attacker-org`'s `webhook_secret` (self-administered).
3. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim-org tracked commit sha with continuous_deployment enabled>",
  "state": "success",
  "context": "ci/attacker",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/whatever" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org_webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` calls `Shipit.github(organization: 'attacker-org')` and succeeds (signature matches attacker's own known secret).
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit regardless of the forged `repository` block — and creates a `success` status, potentially triggering an unauthorized deploy on the victim stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
