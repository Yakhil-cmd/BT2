### Title
Cross-organization commit-status/deploy forgery via webhook signature selected by attacker-controlled `repository.owner.login` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In multi-tenant deployments (multiple GitHub organizations configured under one Shipit instance, as documented in `docs/setup.md` "Using Multiple Github Applications"), `WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the HMAC signature against using a field taken directly from the *unverified* request body, while the event handlers that act on the payload use a *different* field from that same body to decide which repository/stack to write to. These two fields are never cross-checked, breaking the binding "organization that authenticated == repository that is written."

### Finding Description
`verify_signature` computes the organization used to pick the verifying secret from the raw, attacker-supplied JSON body, before the signature has been checked: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization: ...)` looks up a distinct `webhook_secret` per organization key in `secrets.github`, confirming each org's secret is an independent trust boundary in the documented multi-org configuration: [3](#0-2) [4](#0-3) 

Once the signature is "verified" against whatever org `repository.owner.login` claims, `create` dispatches the same raw payload to handlers: [5](#0-4) 

Handlers resolve which `Repository`/`Stack` to act on using a **separate** field, `repository.full_name`, taken from the very same untrusted payload — never re-validated against `repository.owner.login`: [6](#0-5) 

For example, `StatusHandler` looks up commits purely by SHA (global across all stacks/orgs) and writes a GitHub-reported status directly from attacker-controlled fields: [7](#0-6) [8](#0-7) 

Because `repository.owner.login` (used only to pick the verifying secret) and `repository.full_name`'s owner (used to determine the actual target) are two independent JSON fields inside the same forged body, an attacker who legitimately controls (or has learned) the `webhook_secret` for **one** configured organization ("OrgA") can craft a payload where `repository.owner.login = "OrgA"` (passes signature check) while `repository.full_name = "OrgB/some-repo"` or simply omits the owner mismatch entirely for handlers like `StatusHandler` that key off `sha` globally — causing writes against a repository/stack belonging to an organization that never authenticated the request at all.

### Impact Explanation
`Commit#deployable?` and `Commit#schedule_continuous_delivery` gate deploys/continuous delivery on commit status state: [9](#0-8) [10](#0-9) 

A forged `status` webhook, authenticated with OrgA's secret but injecting a "success" status for a commit belonging to OrgB's stack (matched only by SHA, cross-repo), can flip a commit to `deployable?` and trigger `stack.schedule_merges`/continuous delivery for a stack the attacker has no legitimate relationship with — satisfying the Critical bar of "an unauthorized deploy, rollback, or merge," since the organization boundary that is supposed to gate which repository a webhook can affect is not enforced.

### Likelihood Explanation
This requires the attacker to already control a valid `webhook_secret` for at least one organization configured on the instance (e.g., as an org admin who set up their own GitHub App/organization webhook) and knowledge/guessing of a target commit SHA in another org's stack (SHAs are effectively public via GitHub). No repository write access to the victim org is needed — only a valid secret for any one tenant. This is realistic in the documented multi-organization deployment mode that Shipit explicitly supports and ships example config for.

### Recommendation
In `WebhooksController#verify_signature` and in `Webhooks::Handlers::Handler`, require that the organization used to select/verify the webhook secret is derived from — and match — the same `repository.full_name` (or `organization.login`) used by the handlers to resolve the target `Repository`/`Stack`. Concretely: after selecting `github_app` by `repository_owner`, assert that `repository_owner.casecmp?(payload.dig('repository','full_name')&.split('/')&.first)` before processing, and reject (422) on mismatch. Additionally, scope `StatusHandler`'s `Commit.where(sha: ...)` lookup to commits under the verified organization's repositories rather than searching globally by SHA.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md` multi-org config), and a `Stack` for `OrgB/target-repo` tracking commit `deadbee...` which is currently pending/blocked.
2. As a user who legitimately administers `OrgA`'s installed GitHub App (and thus knows `OrgA`'s `webhook_secret`), craft a raw POST body:
```json
{
  "sha": "deadbee...",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and send with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches OrgA's `GitHubApp`, and the signature validates successfully (since it was computed with OrgA's real secret).
5. `StatusHandler#process` finds `Commit.where(sha: "deadbee...")` — which belongs to `OrgB/target-repo` — and calls `create_status_from_github!`, injecting a forged "success" status.
6. This flips `Commit#deployable?` to true for `OrgB`'s commit, potentially triggering `schedule_continuous_delivery`/`schedule_merges` for a stack the attacker never had access to, entirely via a signature that only proved control of `OrgA`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
