This is a valid analog: the binding `verified webhook secret owner (organization used to check the HMAC signature)` != `repository actually written to by the handler (payload's repository.full_name)`.

### Title
Webhook signature is verified against `repository.owner.login`/`organization.login`, but handlers act on the independently-supplied `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports multi-organization GitHub App configuration, where each organization has its own `webhook_secret`. `WebhooksController#verify_signature` selects which secret to verify the HMAC signature against based on `repository.owner.login` (or `organization.login`) taken directly from the unauthenticated JSON payload. However, the handlers that actually mutate application state (e.g. `PushHandler`) resolve the target `Repository`/`Stack` using a *different* field of the same payload: `repository.full_name`. Nothing enforces that these two fields refer to the same repository.

### Finding Description
`verify_signature` computes:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
and uses it to pick the GitHub App/secret: `Shipit.github(organization: repository_owner)`. [1](#0-0) 

Once the signature validates, `create` dispatches the *entire raw payload* to handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [2](#0-1) 

Handlers resolve the affected repository/stack from a **different** payload key, `repository.full_name`, not `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` for every matching stack: [4](#0-3) 

The equality that should hold, but is not enforced, is:
`organization used to authenticate the HMAC (repository.owner.login / organization.login) == organization/repository that handlers act on (repository.full_name)`

In a single-organization deployment (`Shipit.github` with a single top-level config, no per-org keys) this is not exploitable, because there is only one webhook secret for the whole installation, so any signed payload is trusted equally regardless of which repository it names. It only becomes exploitable in the documented multi-organization configuration mode (`github_app_config(organization)` / `TOP_LEVEL_GH_KEYS`), where distinct organizations are configured with distinct `webhook_secret`s [5](#0-4) . An attacker who legitimately controls (or has app-installed on) one configured organization — call it `attacker-org`, and who therefore knows/can produce a valid signature signed with `attacker-org`'s `webhook_secret` — can send a `push` (or `status`/`check_suite`) webhook where `repository.owner.login` = `attacker-org` (so `verify_signature` picks and validates against `attacker-org`'s secret) but `repository.full_name` = `victim-org/victim-repo`. Because the handler only ever consults `repository.full_name`, the forged event is processed as if it legitimately originated from `victim-org`.

### Impact Explanation
For `push` events this triggers `stack.sync_github(expected_head_sha: ...)` on any stack belonging to `victim-org/victim-repo` [4](#0-3) , which drives Shipit's continuous-deployment pipeline (fetching/recording new commits and, combined with `continuous_deployment`, can trigger automatic deploys of attacker-chosen commits) without the attacker ever needing write access, GitHub App installation, or webhook secret knowledge for `victim-org`. This crosses the "cross-repository writes / unauthorized deploy" boundary explicitly listed as in-scope Critical impact, since the deployment-trust binding (secret-verified organization == acted-upon repository) is broken.

### Likelihood Explanation
Requires the deployment to use the multi-organization GitHub App configuration (an organization key configured with its own `webhook_secret`) and requires the attacker to control one such configured organization/app installation (to obtain a validly-signed request), which is a realistic scenario for shared/multi-tenant Shipit installs serving several organizations. No repository write access, GitHub identity impersonation, or possession of `victim-org`'s secret is needed — only crafting the JSON body sent to the shared `/webhooks` endpoint, since `WebhooksController` does not scope the endpoint per-organization.

### Recommendation
Enforce that the organization used to select/verify the webhook secret is the same organization referenced by the fields the handlers actually act on. Concretely, derive `repository_owner` from the same `repository.full_name` field the handlers use for repository/stack resolution (or, symmetrically, make handlers resolve repos strictly by `repository.owner.login` + `repository.name`, matching whatever field was used for signature verification), so a single JSON payload cannot present two different values for "who signed this" vs. "what this event is about."

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (multi-org config per `lib/shipit.rb#github_app_config`).
2. Attacker installs/controls the Shipit-facing GitHub App for `attacker-org` and thus can produce `X-Hub-Signature` valid for `attacker-org`'s `webhook_secret` (e.g., by triggering any real event in a repo they own under `attacker-org`, or by knowing that secret).
3. Attacker crafts a `push` event JSON body where:
   - `repository.owner.login = "attacker-org"`
   - `repository.full_name = "victim-org/victim-repo"`
   - `ref`, `after` set to attacker-chosen branch/SHA.
4. Attacker signs the raw body with `attacker-org`'s secret and POSTs to `/webhooks` with header `X-Github-Event: push`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature.
6. `PushHandler#process` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github` on its stacks — mutating `victim-org`'s stack state using a payload never authenticated by `victim-org`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
