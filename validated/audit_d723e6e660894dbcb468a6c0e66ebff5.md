I have confirmed the analog with concrete file/method support. Here is the finding.

### Title
Cross-organization webhook forgery via mismatched signature-selection field and action field - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In multi-organization Shipit deployments, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`), but the event handlers that actually act on the payload look up the target `Repository`/`Stack` using the independent `repository.full_name` field. Because the field used to select the verification secret is never bound to the field used to select the object being mutated, a party who legitimately controls one organization's GitHub App webhook secret can forge a payload that verifies under their own org's secret while acting on a different organization's repository.

### Finding Description
`WebhooksController#verify_signature` computes `repository_owner` purely from attacker-controlled JSON before any cryptographic check, then fetches the matching `GitHubApp` (and its `webhook_secret`) for that literal string and verifies the raw body against it: [1](#0-0) [2](#0-1) 

This mirrors `lib/shipit.rb#github`, which resolves a distinct `GitHubApp`/secret per organization key when the multi-org config schema (`github: { OrgOne: {...}, OrgTwo: {...} }`) is used, as documented and tested: [3](#0-2) [4](#0-3) 

Once signature verification passes, `Shipit::Webhooks.for_event` dispatches to handlers such as `PushHandler` and the base `Handler`, which resolve the target `Repository`/`Stack` using a *different* payload field, `repository.full_name`, with no cross-check against the `repository_owner`/secret that was used for verification: [5](#0-4) [6](#0-5) 

Pull-request based handlers (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, `EditedHandler`, `ReviewStackAdapter`) exhibit the same pattern, all resolving `Shipit::Repository.from_github_repo_name(params.repository.full_name)` independently of the field used for signature routing: [7](#0-6) [8](#0-7) 

**Binding broken (equality that must hold but doesn't):**
`organization used to select the verifying webhook_secret (repository.owner.login)` ⧧ `organization embedded in repository.full_name used by every handler to select the Repository/Stack that is mutated`.

### Impact Explanation
An attacker who administers a legitimate GitHub App installation for OrgA (and therefore knows OrgA's `webhook_secret` — a normal, unprivileged capability for a tenant admin in a shared multi-org Shipit instance) can craft a webhook body where `repository.owner.login` (or `organization.login`) = `"OrgA"` and sign it with OrgA's secret, while setting `repository.full_name` = `"OrgB/victim-repo"`. `verify_signature` authenticates the request using OrgA's secret and passes; the dispatched handler then acts on OrgB's repository/stack, e.g. triggering `stack.sync_github(expected_head_sha:)` via `PushHandler`, or creating/archiving/unarchiving `ReviewStack`s and mutating `PullRequest` records via the `pull_request/*` handlers — all for a repository the attacker has no legitimate GitHub access to. This is an unauthorized cross-repository write driven entirely by a forged webhook, matching the "cross-repository writes" High/Critical impact category.

### Likelihood Explanation
Exploitation requires the host application to be configured with the documented multi-organization GitHub App schema (`github: { OrgA: {...}, OrgB: {...} }` in `secrets.yml`), which is an explicitly supported and documented configuration. Any tenant admin who legitimately possesses a `webhook_secret` for one organization can immediately exploit this without needing any credential for the target organization, making likelihood high in any multi-tenant Shipit deployment.

### Recommendation
Bind the field used to authenticate to the field used to act: after verifying the signature, re-derive `repository_owner` used for verification and require it to match the owner segment of `repository.full_name` (and `organization.login` where present) before dispatching to handlers, rejecting the request otherwise.

### Proof of Concept
1. Deploy Shipit with multi-org config: `github: { OrgA: { webhook_secret: "secretA", ... }, OrgB: { webhook_secret: "secretB", ... } }`, with `OrgB/victim-repo` registered as a Shipit stack.
2. Attacker (tenant admin of OrgA, knows `secretA`) crafts a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(secretA, body)>` and POST to `/webhooks` with `X-Github-Event: push`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches OrgA's `GitHubApp`, and the signature verifies successfully against `secretA`.
5. `PushHandler#process` resolves stacks via `payload.dig('repository', 'full_name')` = `"OrgB/victim-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on OrgB's stack — an action the attacker could not otherwise trigger without OrgB's webhook secret or GitHub access.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L60-66)
```ruby
          def action
            params.action
          end

          def repo_name
            params.repository["full_name"]
          end
```
