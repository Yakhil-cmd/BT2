### Title
Webhook signature key selection uses an attacker-controlled field that is never cross-checked against the repository the event handlers act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App/webhook secret to use for HMAC verification based on a JSON field taken straight from the unauthenticated request body, while the handlers that actually mutate state (sync stacks, post commit statuses, add/remove team memberships) act on other fields of that same body without re-checking they belong to the organization whose secret validated the signature.

### Finding Description
`verify_signature` derives the signing organization purely from attacker-supplied JSON: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`) — both values are simply JSON strings inside the raw, unauthenticated POST body. `Shipit.github(organization: repository_owner)` uses this value to look up the per-organization config (in the multi-org secrets schema documented in `docs/setup.md`) and returns the `GitHubApp` instance whose `webhook_secret` is used to validate `X-Hub-Signature`: [3](#0-2) 

Critically, `GitHubApp#verify_webhook_signature` treats an unset secret as automatic success: [4](#0-3) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

The multi-org setup documented for Shipit explicitly allows some organizations to be configured with `webhook_secret: # nil`: [5](#0-4) [6](#0-5) 

Once signature verification passes (or is skipped because the chosen org has no secret), the controller dispatches the *entire, unvalidated* JSON body to the registered handlers: [7](#0-6) 

Those handlers (`push_handler.rb`, `status_handler.rb`, `check_suite_handler.rb`, `membership_handler.rb`) resolve the target `Stack`/`Repository`/`Team` from other fields of the same body (e.g. `repository.full_name`, `sha`, `team`), as shown by the existing test coverage that enqueues `GithubSyncJob`/`RefreshCheckRunsJob`/creates `Team`/`Membership` records purely from body content: [8](#0-7) [9](#0-8) 

There is no code path that checks `repository.full_name`'s owner segment (or the team/organization acted on by `membership_handler`) actually equals `repository_owner`/`organization.login`, the field used to pick the signing key. This breaks the intended binding:

`organization whose secret authenticated the request == organization/repository the handler subsequently writes to`

Because `repository.owner.login` and `repository.full_name` (or `organization.login` for membership events) are independent, attacker-controlled JSON keys inside the same unsigned-selection body, an attacker can:
1. Set `repository.owner.login` (or `organization.login`) to an organization configured in Shipit's multi-org secrets with `webhook_secret` blank/nil (per the documented, supported configuration) — this makes `verify_webhook_signature` return `true` unconditionally, with **zero knowledge of any secret**.
2. Populate the rest of the payload (`repository.full_name`, `sha`, `after`, `team`, `member`) to target a *different*, protected organization/repository/stack that Shipit tracks.

The controller/handlers never verify that the two organizations match, so the request is processed as if it were a legitimately signed event for the victim repository.

### Impact Explanation
This allows an unauthenticated, unprivileged attacker to forge cross-repository/cross-organization webhook events (push, status, check_suite, membership) that are accepted and processed for a stack/repository/team belonging to a different, unrelated GitHub organization — as long as *any one* configured org in the Shipit multi-tenant deployment has no `webhook_secret` set (a state the project's own documentation and secrets templates present as a normal/default configuration). Consequences include: forged `push` events that enqueue `GithubSyncJob` against a victim's `Stack` (potentially advancing deploy state/triggering syncs), forged `status`/`check_suite` events that corrupt commit status data used to gate deploys, and forged `membership` events that create/delete `Team`/`Membership` records — directly touching `Shipit.github_teams` authorization data. This crosses the "cross-repository writes" / "escalation into `Shipit.github_teams` authorization" impact bar.

### Likelihood Explanation
Exploitability depends entirely on deployment configuration: it requires a multi-organization Shipit instance where at least one configured org has no `webhook_secret` set. This is not a hardening violation invented for this analysis — it's the exact configuration shown as valid in Shipit's own setup documentation and shipped secrets templates (`webhook_secret: # nil`), so it is a realistic, foreseeable production configuration rather than a hypothetical misuse.

### Recommendation
Bind the field used to select the verification key to the field(s) the handlers actually act on: after verifying the signature, re-derive the organization from the same trusted field the handler uses (e.g. `repository.full_name`'s owner segment / `team`'s org) and reject the request if it does not match `repository_owner`. Additionally, do not allow `verify_webhook_signature` to silently succeed when `webhook_secret` is blank for a *specific* org in a multi-org deployment — require every configured org to define a secret, or explicitly opt an org into "unsigned" mode with additional restrictions instead of implicit bypass.

### Proof of Concept
1. Configure Shipit with two GitHub orgs in `secrets.github`: `victim-org` (with a real `webhook_secret`) and `legacy-org` (with `webhook_secret` left blank/nil, as shown supported in `docs/setup.md`).
2. POST to `/webhooks` with header `X-Github-Event: push` and a crafted, unsigned JSON body:
```json
{
  "repository": { "owner": { "login": "legacy-org" }, "full_name": "victim-org/protected-repo" },
  "after": "<attacker chosen sha>",
  "ref": "refs/heads/master"
}
```
3. `repository_owner` resolves to `legacy-org`; `Shipit.github(organization: "legacy-org")` returns a `GitHubApp` with no `webhook_secret`, so `verify_webhook_signature` returns `true` regardless of the (absent/garbage) `X-Hub-Signature` header — confirmed by the code path at [10](#0-9) .
4. The request proceeds to `Shipit::Webhooks.for_event('push').each { |handler| handler.call(params) }`, and the push handler resolves the target `Stack` from `repository.full_name = "victim-org/protected-repo"`, enqueuing `GithubSyncJob` for that stack as demonstrated by the existing test at [11](#0-10) , even though the request was never authenticated for `victim-org`.

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

**File:** docs/setup.md (L188-209)
```markdown
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

**File:** test/controllers/webhooks_controller_test.rb (L23-41)
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

```

**File:** test/controllers/webhooks_controller_test.rb (L129-165)
```ruby
    test ":membership creates the mentioned team on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Team.count }, 1 do
        post :create, as: :json, body: membership_params.merge(team: {
                                                                 id: 48,
                                                                 name: 'Ouiche Cooks',
                                                                 slug: 'ouiche-cooks',
                                                                 url: 'https://example.com'
                                                               }).to_json
        assert_response :ok
      end
    end

    test ":membership creates the mentioned user on the fly" do
      @request.headers['X-Github-Event'] = 'membership'
      Shipit.github.api.expects(:user).with('george').returns(george)
      assert_difference -> { User.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'george' }).to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can delete an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, -1 do
        post :create, body: membership_params.merge(action: 'removed').to_json, as: :json
        assert_response :ok
      end
    end

    test ":membership can append an user membership" do
      @request.headers['X-Github-Event'] = 'membership'
      assert_difference -> { Membership.count }, 1 do
        post :create, body: membership_params.merge(member: { login: 'bob' }).to_json, as: :json
        assert_response :ok
      end
    end
```
