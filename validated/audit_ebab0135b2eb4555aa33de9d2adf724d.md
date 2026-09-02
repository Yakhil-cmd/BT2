Confirmed. `StatusHandler#process` at [1](#0-0)  matches on `Commit.where(sha: params.sha)` globally, across every stack in the entire Shipit instance, and creates a `success` status which flips `Commit#deployable?` at [2](#0-1) , enabling continuous-delivery auto-deploys via `Status#schedule_continuous_delivery` at [3](#0-2) . Combined with the signature/organization mismatch, this gives a full exploit chain. I have enough to produce the final analog finding.

### Title
Webhook signature is verified against the payload's `repository.owner.login`/`organization.login` while all event handlers act on the independent, unvalidated `repository.full_name` field, allowing any configured GitHub organization to forge webhook events for any other tracked repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController` verifies the GitHub HMAC signature (`X-Hub-Signature`) using a webhook secret selected by `repository_owner`, which is read from the same untrusted JSON body (`repository.owner.login`, falling back to `organization.login`). However, every event `Handler` (push, status, check_suite, pull_request, etc.) determines which `Stack`/`Repository`/`Commit` records to mutate using an entirely different, independently-controlled field of the same body: `repository.full_name`. The HMAC only proves "the sender knows organization X's `webhook_secret`" — it never binds that organization to the `full_name` value the handlers actually act on. In a multi-org Shipit deployment (explicitly supported per `docs/setup.md`), an attacker who legitimately administers one configured GitHub organization (and therefore knows its `webhook_secret`) can forge a signed webhook whose `repository.owner.login`/`organization.login` says "my-org" (to pass signature verification) but whose `repository.full_name` says "victim-org/victim-repo" (to select and mutate a completely different organization's tracked stacks).

### Finding Description
`verify_signature` selects the GitHub App config purely from attacker-controlled payload content and never checks it against the field the handlers use:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [4](#0-3) 

Every handler, however, resolves the target repository/stacks from `repository.full_name`, a sibling field within the same untrusted JSON body that is never cross-checked against `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

`Shipit.github(organization:)` config lookup itself confirms organizations are looked up independently, keyed only by the attacker-supplied `organization:` string with no relation asserted to `full_name`: [6](#0-5) . Multi-org configuration, where each org has its own `webhook_secret`, is the documented setup: [7](#0-6) .

The `StatusHandler` is the most damaging instance of this class, because it queries commits globally, not scoped to any repository derived from the authenticated organization:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 

Note `StatusHandler` doesn't even use `repository.full_name` to scope the query — it matches by `sha` alone across the entire database, so a signature valid for organization A's webhook secret can inject a `success` status onto any commit in the system, regardless of which repository/org it truly belongs to.

### Impact Explanation
Creating a fabricated `success` `Status` on a victim stack's commit flips `Commit#deployable?` to true: [2](#0-1) . If that stack has `continuous_deployment` enabled, `Status#schedule_continuous_delivery` will automatically enqueue and execute a deploy of that commit: [3](#0-2) , and `commits_test.rb` confirms this exact transition triggers `ContinuousDeliveryJob` [8](#0-7) . This is an unauthorized deploy triggered purely by an attacker who is only a legitimate administrator of a *different*, unrelated organization tracked by the same Shipit instance — a cross-organization/cross-repository write and an unauthorized deploy, matching the Critical impact bar in scope.

### Likelihood Explanation
This requires only that the attacker control (own/administer) any one GitHub organization configured on the same multi-tenant Shipit instance — a normal, supported, unprivileged relationship to the victim's organization/repository. No GitHub App private key, no Shipit session, and no access to the victim org's `webhook_secret` are needed. The attacker only needs their own org's already-known `webhook_secret` and the ability to POST a crafted JSON body plus a valid HMAC computed with that known secret. This is trivially achievable by any org administrator.

### Recommendation
After computing `repository_owner` for secret lookup, require that the resolved GitHub organization actually match the owner of the `Repository` model resolved via `repository.full_name` (or vice-versa: derive the webhook secret from the `Repository`/`Stack` already on file for `full_name`, not from attacker-supplied `owner.login`/`organization.login`). Additionally, scope `StatusHandler` (and any other global-lookup handler) queries by the repository resolved from `full_name`, not solely by `sha`, so at minimum the blast radius is limited to the repository the authenticated organization actually owns.

### Proof of Concept
1. Configure Shipit with two GitHub orgs in `secrets.yml`: `attacker-org` (attacker administers, knows its `webhook_secret`) and `victim-org` (tracks a stack with `continuous_deployment: true`, unrelated to attacker).
2. Attacker crafts a `status` webhook payload:
```json
{
  "sha": "<sha of an undeployed commit belonging to a victim-org stack>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(attacker-org's webhook_secret, raw_body)>` and POSTs to `/github/webhooks`.
4. `verify_signature` resolves `repository_owner == "attacker-org"`, fetches `attacker-org`'s `GitHubApp`, and the HMAC verifies successfully [9](#0-8) .
5. `StatusHandler#process` finds the commit by `sha` (ignoring `full_name`/owner entirely) and creates a `success` `Status` on it [1](#0-0) , flipping `deployable?` and triggering an unauthorized continuous deployment on `victim-org`'s stack.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** test/models/commits_test.rb (L233-240)
```ruby
    test "updating state to success triggers new deploy when stack has continuous deployment" do
      @stack.reload.update(continuous_deployment: true)
      @stack.deploys.destroy_all

      assert_difference "Deploy.count" do
        assert_enqueued_with(job: ContinuousDeliveryJob, args: [@stack]) do
          @stack.commits.last.statuses.create!(stack_id: @stack.id, state: 'success', context: 'ci/travis')
        end
```
