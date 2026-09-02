### Title
Webhook signature verified against one organization's secret while push/status/check-suite handlers act on the repository named elsewhere in the same unscoped payload - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub App/HMAC secret to validate a webhook against based solely on `repository.owner.login` (or `organization.login`) taken from the untrusted request body, then hands the *entire* parsed payload to event handlers that resolve the target `Stack`/`Commit` using a *different* field (`repository.full_name`, or in the case of `StatusHandler`, no repository scoping at all). In a multi-organization Shipit deployment (a documented, supported configuration), this breaks the binding "organization whose secret authenticated the request" == "repository/commit the request is allowed to mutate."

### Finding Description
`Shipit.github(organization:)` and the `secrets.github` schema explicitly support hosting several GitHub organizations from one Shipit install, each with its own `webhook_secret`: [1](#0-0) [2](#0-1) 

The webhook entry point picks which org's secret to verify with using a payload field, then verifies the raw body against that org's HMAC secret: [3](#0-2) 

Nothing then re-checks that the org whose secret validated the request actually owns the repository the handler is about to act on. `Handler#stacks`/`Handler#repository_name` — used by `PushHandler`, `LabelCapturingHandler`, `OpenedHandler`, `CheckSuiteHandler`, etc. — resolve the target purely from `repository.full_name` in the same attacker-crafted payload: [4](#0-3) [5](#0-4) 

`StatusHandler` is worse: it does not even use `repository` — it matches `Commit.where(sha: params.sha)` across the *entire* database, with no organization or repository scoping at all: [6](#0-5) 

`CheckSuiteHandler` similarly only filters by `branch`/`head_sha`, again with no ownership check tying the acted-upon stack back to the organization that supplied the valid signature: [7](#0-6) 

Because HMAC verification operates on the raw JSON bytes, an attacker cannot forge a signature for an organization whose secret they do not know — but they do not need to. An administrator of *their own* GitHub App/organization (`OrgOne`) legitimately possesses `OrgOne`'s `webhook_secret` (it is configured by them in the GitHub App settings). Nothing stops them from POSTing directly to Shipit's public `/webhooks` endpoint (it is not restricted to GitHub's IP ranges and performs no other origin check) with a payload where:
- `repository.owner.login` = `"OrgOne"` (so `verify_signature` selects and validates against the secret they legitimately control), and
- `repository.full_name` / `sha` / `check_suite.head_sha` reference a stack or commit belonging to an unrelated `OrgTwo` tracked by the same Shipit instance.

The signature check passes (correct HMAC for `OrgOne`), and the handler then mutates state belonging to `OrgTwo`, an organization the attacker has no relationship with.

### Impact Explanation
This crosses an authentication boundary the report explicitly calls out: the organization that authenticated (`OrgOne`, via its own webhook secret) is not the repository whose state is written (`OrgTwo`). Concrete effects, all achievable by someone who is merely an admin of their own onboarded org in a shared Shipit instance:
- `PushHandler`: force `stack.sync_github(expected_head_sha: <attacker chosen sha>)` on any tracked stack of any other org, at the attacker's chosen branch/SHA.
- `StatusHandler`: forge a `success`/`failure` CI status (`commit.create_status_from_github!`) on any commit anywhere in the instance, regardless of repository, because there is no repository scoping whatsoever. Since Shipit's merge queue and deploy pipelines gate on CI status ("required" statuses in `shipit.yml` `ci.require`), this can be used to fabricate a passing status on another organization's commit to help push it through the merge queue/deploy gating — an unauthorized deploy/merge influence.
- `CheckSuiteHandler`: trigger `schedule_refresh_check_runs!` on another org's commits.

This satisfies the "Critical" bar of "unauthorized deploy, rollback, or merge" / cross-organization writes, achieved purely by an attacker who controls only their own organization's webhook secret in a multi-org deployment — no `ApiClient` token, no repository write access on the victim org, and no interception of GitHub's traffic is required.

### Likelihood Explanation
Requires: (1) the operator runs Shipit in the documented multi-organization mode (explicitly supported and documented), and (2) the attacker is an admin of at least one onboarded organization (a low bar — many orgs may be onboarded to a shared Shipit instance, e.g. internal platform tooling used by many teams). Given that, crafting the payload and computing the HMAC is trivial (it's their own secret), and the webhook endpoint is public and unauthenticated aside from the signature check.

### Recommendation
- After verifying the signature for organization `X`, require that every repository referenced in the payload (`repository.full_name`, and for `status`/`check_suite` events, the resolved `Stack`'s repository owner) actually belongs to organization `X` before dispatching to a handler; reject/drop otherwise.
- In `Shipit::Webhooks::Handlers::Handler`, thread the verified organization through to `stacks`/`repository_name` resolution and filter `Repository.from_github_repo_name` results to repositories owned by that organization.
- Fix `StatusHandler` specifically to scope `Commit.where(sha: params.sha)` to commits whose stack's repository belongs to the verified organization, not the whole database.

### Proof of Concept
1. Deploy Shipit configured for two organizations, `OrgOne` and `OrgTwo`, each with its own tracked stack and its own `webhook_secret` (per `docs/setup.md` "Using Multiple Github Applications").
2. As an administrator of `OrgOne`'s GitHub App, read `OrgOne`'s `webhook_secret` from its own App settings.
3. Craft a JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-in-OrgTwo-repo>",
  "repository": {
    "full_name": "OrgTwo/victim-repo",
    "owner": { "login": "OrgOne" }
  }
}
```
4. Compute `sha1=HMAC-SHA1(OrgOne_webhook_secret, body)` and POST it to `/webhooks` with `X-Github-Event: push` and `X-Hub-Signature: sha1=...`.
5. `verify_signature` resolves `repository_owner` = `"OrgOne"`, fetches `OrgOne`'s `GitHubApp`, and the HMAC matches (attacker knows this secret) — request is accepted.
6. `PushHandler#process` resolves `Repository.from_github_repo_name("OrgTwo/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on `OrgTwo`'s stack, even though the signature only ever proved the request came from someone controlling `OrgOne`'s secret.
7. Similarly, a `status` event signed with `OrgOne`'s secret but containing `sha` of a commit belonging to `OrgTwo`'s stack will have `StatusHandler` create a forged status on that commit, since `Commit.where(sha:)` has no organization/repository scoping at all.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
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
