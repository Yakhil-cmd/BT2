### Title
Webhook signature verification selects the HMAC secret from an attacker-controlled `repository.owner.login`/`organization.login` field that is decoupled from the `repository.full_name` field the handlers actually act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` picks *which* GitHub App config (and therefore which `webhook_secret`) to verify the inbound signature against based on a value read out of the untrusted JSON body itself, while the downstream event handlers resolve the target `Stack`/`Repository` from a *different* field of that same untrusted body. Because the field used to select the verification secret and the field used to select the affected repository are independent and both attacker-supplied, a party who legitimately knows the `webhook_secret` for *one* configured organization can forge a webhook whose signature verifies successfully under that organization's secret but whose payload content (`repository.full_name`) targets a stack belonging to a *different* organization.

### Finding Description
`verify_signature` derives the organization used to look up the verification secret purely from payload content: [1](#0-0) [2](#0-1) 

`repository_owner` is read with `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — both are attacker-controlled fields inside the raw JSON body. `Shipit.github(organization: repository_owner)` then looks up the corresponding `GitHubApp` config, keyed by organization name, from `secrets.github`: [3](#0-2) 

The signature is verified with `github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)`, which HMACs the *entire raw body* with the secret of whichever organization `repository_owner` names: [4](#0-3) 

Once the signature check passes, `create` dispatches the parsed payload to handlers using a completely separate field: [5](#0-4) 

Every handler resolves the target repository/stack via `payload.dig('repository', 'full_name')` (base `Handler#repository_name`/`#stacks`, and repeated per-handler in `PushHandler`, `StatusHandler`, and the `PullRequest::*Handler` classes): [6](#0-5) [7](#0-6) [8](#0-7) 

Docs explicitly describe deployments with multiple, independently-secreted GitHub Apps, one per organization: [9](#0-8) 

The binding that is broken is: **organization authenticated by signature (`repository.owner.login` / `organization.login`) == repository actually written (`repository.full_name`)**. Nothing enforces that `repository.full_name`'s owner segment matches the organization whose secret validated the signature. GitHub itself always sends these consistently, but the webhooks endpoint accepts arbitrary directly-POSTed JSON as long as the `X-Hub-Signature` header matches some configured organization's secret over the raw bytes — the two fields are never cross-checked.

### Impact Explanation
An entity that legitimately administers the GitHub App for one configured organization (and thus knows that organization's `webhook_secret`, which is set by whoever creates/owns that org's GitHub App, per `docs/setup.md`) can forge a signed webhook body where `repository.owner.login`/`organization.login` = their own org (to pick their known secret) but `repository.full_name` = a victim organization's repository. This lets them:
- Fire `push` events to trigger `PushHandler#process` → `stack.sync_github(expected_head_sha: ...)` against a victim's stack/branch.
- Fire `status` events to inject fabricated CI status via `StatusHandler#process` → `commit.create_status_from_github!`, which can flip `Commit#deployable?`/`Stack#merge_status` and trigger `stack.schedule_merges` / `ContinuousDeliveryJob`/`ProcessMergeRequestsJob` for continuous-deployment stacks that are not theirs.
- Fire `pull_request` events to manipulate `ReviewStack` provisioning/archival on a victim's repository review stacks.

This crosses an organization-authentication boundary to act on another organization's repository/stack state, satisfying the "unauthorized deploy/rollback/merge" impact class for engines running multi-org configurations.

### Likelihood Explanation
This requires the target Shipit instance to be configured with more than one GitHub organization (each with a distinct `webhook_secret`), as documented in `docs/setup.md`. Given that configuration, the only prerequisite is knowledge of any *one* configured org's webhook secret — no Shipit account, `ApiClient` token, or GitHub write access to the victim repository is needed, and no TLS interception is required since the attacker can POST directly to the public `/webhooks` endpoint with a self-crafted body and a valid `X-Hub-Signature` computed from their own known secret. This is a realistic misconfiguration-adjacent risk for any deployment onboarding untrusted or semi-trusted organizations under the same Shipit instance.

### Recommendation
After signature verification succeeds for a given organization, cross-check that `repository.full_name`'s owner segment (or `organization.login`) actually belongs to the same organization whose secret validated the signature (e.g., look up the `Repository`/`Stack` and confirm its configured GitHub organization matches `repository_owner` before invoking any handler), rejecting the request with `422` otherwise.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (per `docs/setup.md`'s multi-org example), and a stack under `org-b/victim-repo` with `continuous_deployment: true`.
2. As the administrator (or holder of the webhook secret) of `org-a`'s GitHub App, craft a JSON body:
```json
{
  "repository": {"owner": {"login": "org-a"}, "full_name": "org-b/victim-repo"},
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/forged"
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(org-a-secret, raw_body)>` and POST it to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` resolves `repository_owner == "org-a"`, verifies successfully against `org-a`'s secret over the whole raw body (`app/controllers/shipit/webhooks_controller.rb:24-30`, `lib/shipit/github_app.rb:76-83`).
5. `StatusHandler#process` then looks up `Commit.where(sha: params.sha)` — belonging to `org-b/victim-repo` — and calls `create_status_from_github!`, potentially flipping the commit to `success` and triggering `stack.schedule_merges`/continuous deployment for `org-b`'s stack, despite the signature only proving knowledge of `org-a`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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
