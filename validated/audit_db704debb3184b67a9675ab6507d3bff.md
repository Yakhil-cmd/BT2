### Title
Webhook `X-Hub-Signature` binds only the payload's `repository.owner.login`, letting a signature valid for one organization authorize webhook actions against any repository named in `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC against using `repository_owner`, which is read from the same untrusted JSON body (`params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`). Once the HMAC is accepted, the entire raw body — including the *separate* `repository.full_name` field — is handed unchanged to the event handlers. The handlers (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, PR handlers, etc.) resolve the target `Stack`/`Repository` using `repository.full_name`, not `repository.owner.login`. Because Shipit's multi-org config keys a distinct `webhook_secret` per organization, an attacker who legitimately controls a Shipit-configured organization's webhook secret (e.g. their own GitHub App installation on org "attacker-org") can compute a valid HMAC over a payload where `repository.owner.login = "attacker-org"` (the field used to pick the secret) but `repository.full_name = "victim-org/victim-repo"` (the field the handler actually acts on).

### Finding Description
`verify_signature` looks up the signing key based on one payload field: [1](#0-0) [2](#0-1) 

The HMAC is computed with `Shipit.github(organization: repository_owner).verify_webhook_signature`, which loads the per-organization `webhook_secret` from `Shipit.github_app_config(organization)`: [3](#0-2) [4](#0-3) 

Once the signature is accepted, `create` re-parses the same raw body and dispatches it, unchanged, to every registered handler: [5](#0-4) 

All handlers resolve the affected `Repository`/`Stack` from a *different* field of the payload — `repository.full_name` — which was never part of the binding used to choose the signing key: [6](#0-5) 

For example `PushHandler` immediately triggers a GitHub sync/deploy pipeline for whatever stacks match that `full_name`: [7](#0-6) 

`StatusHandler` writes a CI status for an arbitrary commit `sha` present anywhere in the datastore, with no repository ownership check at all beyond the sha matching a `Commit` row: [8](#0-7) 

`CheckSuiteHandler` similarly schedules a check-run refresh for any stack whose branch/sha matches, resolved the same way through `stacks` (i.e., via `repository.full_name`): [9](#0-8) 

**The broken binding, stated as an equality that the engine fails to enforce:**
`organization authenticated by verify_signature (repository.owner.login / organization.login)` MUST equal `repository written to by the handler (repository.full_name's owner)`, but the engine never checks this equality — it only checks that the signature is valid for whichever organization the `owner.login` field claims, and separately trusts `full_name` for routing.

Before the attack: only the legitimate GitHub App installation for `victim-org` (holding `victim-org`'s `webhook_secret`) can produce accepted push/status/check_suite events for `victim-org/victim-repo`'s stacks.

After the attacker's request: any party holding a *valid webhook secret for any one configured organization* (including one they legitimately administer, e.g. `attacker-org`) can produce accepted events that are processed as if they originated from `victim-org/victim-repo`, because the handler layer trusts `repository.full_name` independently of the field the signature check validated.

### Impact Explanation
This crosses a repository-authorization boundary without repository write access or a Shipit session/token: it lets a party with only a secret for organization A forge push/status/check-suite events for stacks belonging to organization B. Depending on handler reached this can:
- Force `PushHandler` to invoke `Stack#sync_github(expected_head_sha:)` for a victim stack (spurious sync events / resource churn against a repo the attacker does not own).
- Force `StatusHandler` to inject a forged CI status (`create_status_from_github!`) onto an existing `Commit` row for any sha, which — if Shipit or its `shipit.yml` gates deploy eligibility on stored CI status — can be used to mark an otherwise-unqualified commit as passing, contributing to an unauthorized deploy decision.
- Force `CheckSuiteHandler` to schedule check-run refreshes for a victim stack's commits.

This matches the "High" bucket in scope (escalation across a repository/authentication boundary via a payload field never covered by the same verification as the field used to authenticate) and can contribute toward the "Critical" outcome of an unauthorized deploy if a stack's deploy gating relies on stored `Status`/check-run state. I was not able to fully verify, given the remaining tool budget, whether any stack's deploy-eligibility logic (`Stack` status/lock checks) treats a forged `Commit#create_status_from_github!` entry as sufficient to unblock a deploy — that would need to be confirmed by inspecting `Stack`/`Commit`/deploy-eligibility code (e.g. `Shipit::Stack#sync_github`, `Commit#create_status_from_github!`, and any `required_status_contexts` logic) before treating the Critical-level claim as proven.

### Likelihood Explanation
Requires the attacker to control a legitimately configured organization's `webhook_secret` in a multi-organization Shipit deployment (`secrets.github` keyed by org, per `Shipit.github_app_config`/`TOP_LEVEL_GH_KEYS`) — i.e., they must be an onboarded tenant/org admin on the same Shipit instance, but need no privileges on the victim organization or repository, no Shipit session, and no API token. This is a realistic multi-tenant configuration scenario documented in `docs/setup.md`'s "multiple GitHub applications" schema.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), cross-validate that `repository.full_name`'s owner segment matches the organization whose `webhook_secret` was used to authenticate the request (i.e., reject if `repository.full_name.split('/').first != repository_owner`), so the field selecting the trust key and the field used for routing/authorization are the same authenticated value.

### Proof of Concept
1. Configure Shipit with two organizations, `attacker-org` and `victim-org`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md` multi-org schema).
2. As the party controlling `attacker-org`'s webhook secret, craft a JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac using attacker-org's webhook_secret>` over the raw body, per `verify_webhook_signature` at [4](#0-3) .
4. POST to `/github/webhooks` with header `X-Github-Event: push`. `verify_signature` selects `attacker-org`'s secret via `repository_owner` and accepts the signature; `create` then dispatches the same body to `PushHandler`, which resolves stacks via `repository.full_name = "victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack — a forged event for a repository the requester does not control.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
