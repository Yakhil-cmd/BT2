### Title
Unscoped commit-status webhook handler lets any authenticated GitHub organization forge CI status on commits belonging to other organizations' stacks, enabling unauthorized deploys - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
This is a valid analog of the reported bug class. The static-nonce report is fundamentally about a value (the nonce) that is used to protect an operation but is never bound to the specific context (key/message) it's supposed to protect, allowing cross-context reuse. In Shipit, the same class of binding failure exists between **the GitHub organization whose webhook signature authenticates a request** and **the repository/commit that the resulting handler actually mutates**. The `status` webhook handler updates commit CI state using only the commit SHA, with no check that the SHA belongs to a repository owned by the organization that signed the request.

### Finding Description
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to validate the inbound signature against, based on an attacker-controlled field in the unauthenticated JSON body: [1](#0-0) [2](#0-1) 

This only proves that *some* configured organization's secret matches the *whole* raw body - it establishes "this request came from organization X" but does nothing to constrain which repository/commit the payload is allowed to affect. Once verification passes, the entire raw payload (still fully attacker-controlled aside from being correctly signed by org X's own key) is dispatched to handlers: [3](#0-2) 

The `status` event handler consumes this payload and updates commit state by SHA alone, with **no repository/organization scoping whatsoever**: [4](#0-3) 

Contrast this with other handlers (`PushHandler`, `PullRequest::*Handler`), which explicitly resolve `Repository.from_github_repo_name(params.repository.full_name)` before acting, scoping the mutation to the repository the payload claims to be about: [5](#0-4) [6](#0-5) 

`StatusHandler` has no equivalent check. It looks up `Commit.where(sha: params.sha)` globally across the entire Shipit installation and writes a status for every matching commit, regardless of which repository/stack that commit belongs to, and regardless of the `repository.owner.login` value used earlier only to pick a signing secret.

Shipit supports (and documents) exactly the multi-tenant configuration that makes this exploitable: a single Shipit instance can serve multiple independent GitHub organizations, each with its own GitHub App and `webhook_secret`: [7](#0-6) [8](#0-7) 

The commit status written this way is not cosmetic - it directly feeds Shipit's deploy-gating logic: [9](#0-8) 

**Binding broken (equality that should hold but doesn't):**
`organization authenticated by X-Hub-Signature` == `organization owning the repository/commit whose status is written`

Before the attacker's request: only GitHub, holding org X's real webhook secret, can produce commits/statuses for org X's own repositories.
After the attacker's request: any tenant organization X configured on the shared Shipit instance, using only its own legitimate `webhook_secret` (no compromise of anyone else's secret, no Shipit session, no API token), can post a `status` event that is valid for org X but whose `sha`/`state`/`context` target a commit that actually belongs to a completely different tenant organization Y's stack.

### Impact Explanation
A forged "success" status for a `required`/`blocking` CI context on a commit belonging to another organization's stack can make that commit appear deployable even though its real CI never passed (or actually failed). Since `blocking?`/`required?` gate whether a commit can be shipped, this is a path to an **unauthorized deploy** of unverified code in another tenant's stack — one of the explicitly listed Critical impacts (unauthorized deploy). It requires no privileged Shipit access, no theft of another org's `webhook_secret`, and no compromise of GitHub itself - only possession of a legitimate GitHub App/webhook credential for the attacker's own, unrelated organization hosted on the same Shipit instance.

### Likelihood Explanation
Likelihood is limited by two factors: (1) the attacker needs to run/administer their own GitHub App installed on the shared Shipit instance (a normal, unprivileged, documented multi-org deployment configuration - not a privileged Shipit account), and (2) the attacker needs to know a target commit SHA in the victim stack, which is typically not secret (commit SHAs are visible via GitHub, PRs, CI logs, or Shipit's own public-facing UI/API for that stack). Both preconditions are realistic for a multi-tenant Shipit deployment, making this a practically reachable path rather than a purely theoretical one.

### Recommendation
In `StatusHandler#process` (and ideally in the shared `Handler#stacks`/`Handler#repository_name` lookups used by all handlers), scope the `Commit.where(sha: params.sha)` lookup to commits belonging to the repository identified by `repository_owner`/`repository.full_name` that was actually verified in `WebhooksController#verify_signature`, e.g. by joining through `Stack -> Repository` and confirming `repository.owner == repository_owner` before updating any commit. More generally, thread the verified organization/repository identity from `WebhooksController` into every handler as a required, checked parameter rather than trusting the same unauthenticated payload fields for both signature-selection and business-logic purposes.

### Proof of Concept
1. Attacker controls "attacker-org", a legitimate but unprivileged tenant with its own GitHub App/`webhook_secret` configured in this shared Shipit instance (per `docs/setup.md`'s multi-org config).
2. Attacker discovers a commit SHA belonging to "victim-org/victim-repo" (a different stack on the same instance) that has a `required`/`blocking` status context, e.g. `ci/tests`.
3. Attacker builds a `status` event payload:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/tests",
     "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/any-repo"}
   }
   ```
4. Attacker signs the raw body with `attacker-org`'s own real `webhook_secret` (`sha1=HMAC(secret, body)`) and POSTs it to Shipit's webhook endpoint with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `repository_owner` to `"attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and successfully verifies the signature using the attacker's own valid secret.
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit (owned by a stack the attacker has no legitimate relationship to), and calls `commit.create_status_from_github!(params)`, writing a fabricated `success` status for context `ci/tests` on victim-org's commit.
7. Victim-org's stack now reports the required check as green, potentially permitting a deploy of a commit whose real CI never passed.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** docs/setup.md (L181-209)
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

**File:** app/models/shipit/status/common.rb (L46-52)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end

      def required?
        commit.required_statuses.include?(context)
      end
```
