This confirms the mismatch: `WebhooksController#verify_signature` selects and verifies against the GitHub App keyed on `params.dig('repository','owner','login')` (the "organization"), while every event handler resolves the actual target purely from `params.repository.full_name` via `Repository.from_github_repo_name`, which splits on `/` and does an independent `owner/name` lookup that has no relationship to the app used for signature verification.### Title
Webhook signature is verified against the GitHub App of `repository.owner.login` while every event handler resolves and mutates state for `repository.full_name` — the two fields are never checked to match - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App (and thus the `webhook_secret` used to validate `X-Hub-Signature`) using `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). Every event handler (`PushHandler`, `PullRequest::*Handler`, etc.), however, resolves the actually-affected `Repository`/`Stack` purely from `params.repository.full_name` via `Repository.from_github_repo_name`, an independent string that is never checked for consistency with `repository.owner.login`. In a multi-organization deployment (`docs/setup.md` "Using Multiple GitHub Applications", `Shipit.github_app_config`) where different GitHub Apps/organizations have different (or absent) `webhook_secret`s, an attacker who can deliver a request to `/webhooks` can pick whichever organization's signing key is weakest/blank to pass `verify_signature`, then supply a `repository.full_name` belonging to a *different*, properly-secured organization's stack, causing the handler to act on that stack without ever proving knowledge of its real webhook secret.

### Finding Description
The binding that should hold is:
`organization whose webhook_secret authenticated the request == organization owning the repository the handler will act on`

In `app/controllers/shipit/webhooks_controller.rb`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` maps the `organization` string directly to a configured GitHub App (`github_app_config`), each of which can have its own, independently configured `webhook_secret`: [3](#0-2) 

`GitHubApp#verify_webhook_signature` additionally treats a blank `webhook_secret` as automatically verified:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 

Meanwhile every event handler ignores `repository.owner.login` entirely and looks up the target purely from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [5](#0-4) 

and `Repository.from_github_repo_name` does its own independent split of the `owner/name` string:
```ruby
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [6](#0-5) 

`PushHandler`, which drives `stack.sync_github` (and ultimately `GithubSyncJob`), is a concrete example of a state-mutating handler keyed purely on `repository.full_name`: [7](#0-6) 

Because `repository.owner.login` and `repository.full_name` are two entirely independent JSON fields in the same attacker-controlled payload, and neither is cross-checked against the other, nothing prevents the value used for authentication (`owner.login`) from diverging from the value used for authorization/target-selection (`full_name`). In particular:
- If any configured GitHub organization has no `webhook_secret` set (explicitly allowed and shown as a valid config in `docs/setup.md` / `config/secrets.development.example.yml`, and defaulting to `nil`), `verify_webhook_signature` returns `true` unconditionally for that organization's name, regardless of the actual signature header sent.
- An attacker only needs `repository.owner.login` to equal that unsecured (or otherwise weaker/known-secret) organization's name to pass `verify_signature`, while setting `repository.full_name` to `"<secured-org>/<repo>"` to target a stack belonging to a completely different, properly secured organization.

### Impact Explanation
This breaks the deployment-trust binding between the organization that cryptographically authenticated the webhook and the repository whose state gets mutated. Handlers reachable this way include `PushHandler` (forces `GithubSyncJob`/`stack.sync_github`, which recomputes commits and can feed into deploys) and the `PullRequest::*` handlers (which can archive/unarchive review stacks, and update pull-request state used by merge/deploy gating). This is a cross-organization/cross-repository forgery of webhook events without possessing the target organization's real webhook secret — landing in the "cross-repository writes" / unauthorized state-mutation category the rules call Critical-tier.

### Likelihood Explanation
Likelihood is High in any multi-app deployment (the officially documented "Using Multiple Github Applications" configuration in `docs/setup.md`) where at least one configured organization has a blank/weak `webhook_secret`, or where an attacker can otherwise determine one organization's `webhook_secret` (e.g., a lower-trust org they control being onboarded to the same Shipit instance) while wanting to forge events for a different, higher-trust org/repo on the same instance. `/webhooks` is an unauthenticated, internet-reachable POST endpoint by design (that's the whole point of GitHub webhooks), so no session, API token, or GitHub write access is required to attempt delivery — only knowledge (or absence) of one organization's webhook secret among those configured on the instance.

### Recommendation
Cross-validate `repository.owner.login` (the field used to select the signing GitHub App) against `repository.full_name`'s owner segment before dispatching to any handler, rejecting the webhook if they disagree. Additionally, never treat a blank/unset `webhook_secret` as "verification passed" — require every configured organization to have a `webhook_secret`, or explicitly opt into insecure mode with a loud, single global flag rather than silently succeeding per-organization in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
Preconditions: Shipit instance configured with multiple GitHub Apps (per `docs/setup.md`), e.g. `OrgAttacker` (no `webhook_secret` configured) and `OrgVictim` (properly configured `webhook_secret`, with a tracked stack for `OrgVictim/secret-repo`).

1. Attacker crafts a `push` webhook payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha already reachable/known>",
  "repository": {
    "full_name": "OrgVictim/secret-repo",
    "owner": { "login": "OrgAttacker" }
  }
}
```
2. Attacker POSTs this to `/webhooks` with `X-Github-Event: push` and any `X-Hub-Signature` value (or omits a real HMAC entirely).
3. `WebhooksController#verify_signature` computes `repository_owner => "OrgAttacker"`, loads `Shipit.github(organization: "OrgAttacker")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — the request passes signature verification without any valid signature.
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgVictim/secret-repo")`, finds the real victim `Stack`, and calls `stack.sync_github(expected_head_sha: ...)`, enqueuing `GithubSyncJob` and mutating the victim stack's commit state — despite the attacker never having proven knowledge of `OrgVictim`'s webhook secret.

Note: I could not fully trace downstream effects of a forced `sync_github`/`GithubSyncJob` run all the way to an actual unauthorized deploy trigger within the indexed subset of the codebase (e.g., interactions with continuous-deployment scheduling), so the "unauthorized deploy" escalation beyond forged state mutation/stack sync is inferred from `Stack.schedule_continuous_delivery`/`ContinuousDeliveryJob` wiring rather than directly verified end-to-end.

### Citations

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
