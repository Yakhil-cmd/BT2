### Title
Payload-controlled organization used to select webhook HMAC secret lets one tenant's webhook forge events for another tenant's repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In a multi-organization Shipit deployment (`config/secrets.yml` with a top-level org key per GitHub App, as documented in `docs/setup.md` "Using Multiple Github Applications"), the webhook signature is verified using a secret that is selected from an **attacker-controlled field of the same unverified payload**, while the object actually mutated by the handler is read from a **different field of that payload**. These two fields are never cross-checked, breaking the binding "organization that authenticated == repository that is written."

### Finding Description
`WebhooksController#verify_signature` picks which `GitHubApp`/`webhook_secret` to validate the HMAC against by reading the organization straight out of the untrusted JSON body, before the signature has been checked: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`) — pure payload content, not covered by any prior verification. `Shipit.github(organization: repository_owner)` then resolves to a specific `GitHubApp` instance and its own `webhook_secret`, per the multi-tenant config format: [3](#0-2) 

Once the HMAC passes (using whichever secret matched the attacker-chosen `repository_owner`), `WebhooksController#create` dispatches the *entire raw payload* to event handlers: [4](#0-3) 

Handlers, however, resolve the actual `Stack`/`Repository` to mutate from `repository.full_name`, a **separate** field of the same payload that was never used in the signature-selection step and is not required to match `repository.owner.login`: [5](#0-4) [6](#0-5) 

`Repository.from_github_repo_name` looks the repository up globally in the database, with no scoping to `repository_owner`/the org whose secret validated the request. Consequently, an attacker who legitimately administers a GitHub App for one org configured in this multi-tenant Shipit instance (`OrgOne` in the example config) knows that org's `webhook_secret` and can compute a valid HMAC over **any** JSON body of their choosing — including a body where `repository.owner.login`/`organization.login` = `"OrgOne"` (so the correct secret is selected and the signature passes) but `repository.full_name` = `"OrgTwo/victim-repo"` (an entirely different tenant's repository).

### Impact Explanation
This breaks the intended trust boundary between tenants in a multi-org Shipit installation: possession of *any one* configured org's webhook secret is sufficient to forge `push`, `status`, `check_suite`, `pull_request`, `membership`, etc. events that are applied to *any other* org's `Stack`/`Repository`/`Commit` records, because the handlers never re-validate that the mutated repository belongs to the organization whose secret authenticated the request. Concretely:
- A forged `push` event drives `PushHandler#process` to call `stack.sync_github(expected_head_sha: params.after)` on a victim stack with an attacker-chosen SHA [7](#0-6) .
- A forged `status` event can create/alter `Commit` CI status records for a victim's commits, which factor into merge/deploy readiness for a stack the attacker does not own.

Because this can result in cross-repository/cross-org state manipulation and can influence deploy/merge decisions for a repository the attacker has no authorization over, it meets the High/Critical bar of "cross-repository writes" / "unauthorized deploy or merge."

### Likelihood Explanation
Requires the attacker to control a legitimate GitHub App installation/webhook secret for at least one organization already configured in a multi-org Shipit deployment (a scenario explicitly supported and documented by this engine, see `docs/setup.md` "Using Multiple Github Applications"). This is a realistic and unprivileged-with-respect-to-the-victim-org scenario: the attacker is a legitimate tenant of the Shipit instance for their own org, but has zero authorization on the victim org/repository, and the vulnerable code path is reachable by anyone able to POST to the public `/github/webhooks` endpoint (no Shipit session, `ApiClient` token, or repository write access to the victim repo is needed).

### Recommendation
After signature verification succeeds, re-derive/require that `repository.owner.login` (or `organization.login`) used to select the verifying secret is the same organization that owns the `repository.full_name`/`stack` being mutated, and reject the event otherwise. Alternatively, scope `Repository.from_github_repo_name` lookups (and all handler logic) to the organization that was cryptographically verified, rather than trusting an independent field in the same unauthenticated JSON body.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, e.g. `OrgOne` (attacker-controlled app/secret `S1`) and `OrgTwo` (victim, hosts stack for `OrgTwo/victim-repo`), per the multi-app schema in `docs/setup.md`.
2. Attacker, as the legitimate admin of `OrgOne`'s GitHub App, knows `S1`.
3. Attacker crafts a `push` webhook JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "<attacker-chosen-sha>",
     "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgTwo/victim-repo" }
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S1, body)` and sends the POST to `/github/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgOne"`, looks up `OrgOne`'s `GitHubApp`, and the HMAC verifies successfully against `S1`.
6. `PushHandler` reads `repository.full_name` = `"OrgTwo/victim-repo"`, finds `OrgTwo`'s stack via `Repository.from_github_repo_name`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` — mutating a victim organization's stack despite the attacker having no credentials for `OrgTwo`.

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
