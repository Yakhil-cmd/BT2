### Title
Webhook signature verification is keyed off `repository.owner.login`/`organization.login` while event handlers act on the unrelated `repository.full_name` field, allowing signature-check bypass across GitHub organizations - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp`/`webhook_secret` used to validate `X-Hub-Signature` based on `repository_owner`, computed as `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) . Every event handler, however, determines which `Repository`/`Stack` to mutate using a completely different field of the same JSON body: `payload.dig('repository', 'full_name')` [2](#0-1) . This is the same class of bug as the reported issue: two fields that are supposed to represent "the same" authorized entity are checked/validated against one representation and acted upon using another, uncoupled representation.

### Finding Description
Shipit supports multiple GitHub Apps/organizations, each with its own `webhook_secret`, keyed by organization name in `secrets.github.<org>` [3](#0-2) [4](#0-3) . `Shipit.github(organization:)` looks up the config for the named organization and instantiates a `GitHubApp` bound to that organization's `webhook_secret` [5](#0-4) . `GitHubApp#verify_webhook_signature` trivially returns `true` when that organization's `webhook_secret` is blank/nil: `return true unless webhook_secret` [6](#0-5) .

The equality the code implicitly assumes is:
```
organization used to select the verifying secret == organization that owns the repository actually acted upon
```
In reality:
- The **verifying secret is selected** using `repository.owner.login` (or `organization.login`) — `repository_owner` in the controller.
- The **repository/stack actually mutated** is selected using `repository.full_name` — `Handler#repository_name`.

Since these are two independent fields inside the same attacker-controlled JSON body, an attacker can submit a payload where `repository.owner.login` is set to some organization `OrgA` that is configured in this Shipit instance but has no `webhook_secret` set (a common, explicitly documented configuration pattern — see the `webhook_secret: # nil` comments in `secrets.development.example.yml`/`secrets_double_github_app.yml`), while `repository.full_name` is set to `"OrgB/some-repo"`, a completely different, "protected" organization/repository that Shipit tracks with its own stacks. Because `Shipit.github(organization: 'OrgA')` resolves to a `GitHubApp` whose `webhook_secret` is nil, `verify_webhook_signature` returns `true` unconditionally, regardless of what signature header (if any) was sent, and regardless of the fact the payload's actual content (`repository.full_name`) targets `OrgB`. The handler dispatch (`Webhooks.for_event(event).each { |handler| handler.call(params) }`) then runs against the full, unverified-for-OrgB payload [7](#0-6) , resolving the target `Stack` purely from `repository.full_name` [2](#0-1) .

For example, `StatusHandler#process` creates a `Status` for any commit matching the attacker-supplied `sha`/`state` with no further authentication [8](#0-7) , and `PushHandler#process` triggers `stack.sync_github(expected_head_sha:)` for any stack matching the (attacker-controlled) branch of the (attacker-controlled) `repository.full_name` [9](#0-8) . Creating a forged "success" `Status` triggers `schedule_continuous_delivery`, which can lead `ContinuousDeliveryJob` to trigger an actual `Deploy` on stacks with `continuous_deployment: true` [10](#0-9) [11](#0-10) .

### Impact Explanation
This breaks the deployment-trust binding "an organization that authenticated versus the repository that is written." An unprivileged attacker who merely knows the name of any configured-but-secretless organization in a multi-org Shipit deployment can forge webhook payloads for a different organization's repositories and: create fake CI `Status`es, trigger continuous-delivery deploys on stacks belonging to that unrelated (properly secured) organization, or trigger `GithubSyncJob`/`RefreshCheckRunsJob` for arbitrary tracked repositories — all while the signature check nominally "passes." This satisfies the "unauthorized deploy" High/Critical impact category.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit deployment, and (2) at least one configured organization without a `webhook_secret`. Both conditions are explicitly supported and even shown as the default/example configuration in this codebase's own docs and fixtures (`webhook_secret: # nil` appears repeatedly in `config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`, and `test/dummy/config/secrets_double_github_app.yml`), making this a realistic operational configuration rather than a contrived edge case. No credentials, tokens, or prior access are required — only knowledge of one configured org name and any tracked repository's `full_name`.

### Recommendation
Bind signature verification to the same repository identity that handlers use to select the target `Stack`/`Repository`. Concretely, derive the organization used for `Shipit.github(organization:)` from `repository.full_name`'s owner segment (or otherwise ensure `repository_owner` and the acted-upon `repository.full_name`'s owner are the same, verified value) before dispatching to handlers, and reject payloads where they diverge. Additionally, consider treating a missing per-organization `webhook_secret` as "verification not configured — reject" rather than "verification trivially passes," at least when other organizations in the same deployment do have secrets configured.

### Proof of Concept
1. Configure Shipit with two organizations: `OrgA` (no `webhook_secret`) and `OrgB` (has stacks tracked, e.g. `OrgB/protected-repo` with `continuous_deployment: true`), per the multi-org schema in `docs/setup.md`.
2. Attacker sends `POST /github/webhooks` (or the configured webhook path) with header `X-Github-Event: status` and body:
```json
{
  "sha": "<sha of a commit on OrgB/protected-repo>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/protected-repo" }
}
```
No valid `X-Hub-Signature` is required.
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: 'OrgA')`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally [6](#0-5) .
4. `StatusHandler#process` runs against the full payload and creates a `success` `Status` for the matched commit under `OrgB/protected-repo`'s stack [8](#0-7) , which can trigger continuous delivery/deploy for that stack — despite the attacker having no relationship to `OrgB` or its secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** lib/shipit.rb (L170-181)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
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

**File:** app/models/shipit/status.rb (L18-20)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

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
