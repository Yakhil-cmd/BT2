### Title
Cross-Organization Webhook Forgery via Unbound `repository.owner.login` vs `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
### Finding Description
`WebhooksController#verify_signature` selects which GitHub App (and therefore which HMAC `webhook_secret`) to validate an inbound webhook against by reading `repository.owner.login` (or `organization.login`) straight out of the untrusted, attacker-suppliable JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves the app/secret purely from that string, using a case-insensitive lookup into the multi-org `secrets.github` config documented for the "Using Multiple Github Applications" setup: [3](#0-2) [4](#0-3) 

Once the signature check passes, `create` re-parses the *entire* raw body and dispatches it, unmodified, to the registered handlers (e.g. `Handlers::PushHandler`) for the `push` event: [5](#0-4) [6](#0-5) 

The push handler is documented/tested to resolve the target `Stack`/`Repository` from `params['repository']['full_name']` (not from `repository.owner.login`), as shown by the webhook fixtures and tests that key stacks off `push_master`'s `repository.full_name` while `repository_owner` is derived from a separate `owner.login` field: [7](#0-6) [8](#0-7) 

Nowhere in this path is `repository.full_name`'s owner segment cross-checked against the `repository.owner.login`/`organization.login` value that selected the signing secret. The equality that the signature is supposed to guarantee — "organization whose secret authenticated this request" == "organization owning the repository whose stack gets written to" — is never enforced; only the *first* field is covered by the HMAC-verified organization lookup, while the *second* field (the one the handler actually acts on) is taken from the same attacker-controlled body without being tied back to that lookup.

### Impact Explanation
In a multi-org deployment (the documented `github: { orgA: {...}, orgB: {...} }` config, exercised in `test/dummy/config/secrets_double_github_app.yml`), anyone who legitimately controls a GitHub App installation for **any one** of the configured organizations (e.g. `orgA`) knows that organization's `webhook_secret`. Because `repository_owner` (used only to pick the verification secret) is independent of `repository.full_name` (used by `Handlers::PushHandler` to pick the `Stack`), that person can forge a signed webhook body where `repository.owner.login = "orgA"` (so the signature validates with the secret they know) but `repository.full_name = "orgB/victim-repo"` and an arbitrary `after` SHA / `ref`. This lets them enqueue `GithubSyncJob` and drive `Stack` state (last known revision, commit tracking) for a repository/organization they do not control and never authenticated against, crossing the "organization authenticated vs. repository written" trust boundary defined for this engine. Depending on downstream sync/continuous-deployment configuration this can influence what commit is considered deployable/deployed for another tenant's stack — an unauthorized cross-repository effect within the meaning of the engine's Critical impact bucket ("cross-repository writes").

### Likelihood Explanation
Exploitability requires the attacker to control the webhook secret of at least one organization configured on the same multi-tenant Shipit instance — a realistic scenario for the exact "Using Multiple Github Applications" deployment mode the engine documents and tests (`docs/setup.md`, `test/dummy/config/secrets_double_github_app.yml`). No Shipit session, `ApiClient` token, or GitHub write access to the *victim* org is needed; only the ability to install/configure a GitHub App for a co-tenant org, which is exactly the "unprivileged attacker" relative to the victim repository. Single-org deployments (the default, single `secrets.github` block) are not affected because there is only one secret/organization to begin with, and `repository_owner` and `full_name`'s owner necessarily agree there.

### Recommendation
In `WebhooksController#verify_signature` / the push (and other repository-scoped) handlers, enforce that the organization used to select the signing secret is the same organization embedded in `repository.full_name` before acting on the payload — e.g., require `params.dig('repository','full_name').split('/').first.casecmp(repository_owner) == 0` prior to dispatching to handlers, or have handlers themselves validate the repository's owner against the authenticated organization context passed down from the controller instead of trusting `full_name` in isolation.

### Proof of Concept
1. Configure Shipit in multi-org mode with two organizations, `orgA` and `orgB`, each with their own GitHub App and `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As the operator/owner of `orgA`'s GitHub App, obtain `orgA`'s `webhook_secret` (legitimately available to them).
3. Craft a `push` event JSON body:
   ```json
   {
     "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" },
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>"
   }
   ```
4. Compute `X-Hub-Signature: sha1=<hmac-sha1(orgA_webhook_secret, body)>` and POST to `/github_webhooks`.
5. `verify_signature` resolves `Shipit.github(organization: 'orgA')` (per `repository.owner.login`), validates successfully against the forged signature.
6. `create` dispatches the full body to `Handlers::PushHandler`, which resolves the target stack via `repository.full_name = "orgB/victim-repo"` and enqueues `GithubSyncJob`/updates commit tracking for `orgB`'s stack — despite the request never having been authenticated by `orgB`.

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

**File:** app/models/shipit/webhooks.rb (L6-9)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
```

**File:** test/controllers/webhooks_controller_test.rb (L23-32)
```ruby
    test ":push with the target branch queues a GithubSyncJob" do
      request.headers['X-Github-Event'] = 'push'

      parsed_body = JSON.parse(payload(:push_master))
      expected_head_sha = parsed_body["after"]

      assert_enqueued_with(job: GithubSyncJob, args: [stack_id: @stack.id, expected_head_sha:]) do
        post :create, body: parsed_body.to_json, as: :json
      end
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L216-218)
```ruby
    def repository_params
      { repository: { owner: { login: 'shopify' } } }
    end
```
