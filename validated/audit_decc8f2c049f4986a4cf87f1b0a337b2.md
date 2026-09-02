## Finding

The webhook signature check in `WebhooksController` selects **which** GitHub App's secret to verify against using the merged Rails `params` object, while the actual **repository/stack that gets acted upon** is derived from a completely separate parse of the raw request body. These two sources of "which organization/repo this event is for" are not required to agree, and only the body is covered by the HMAC signature. [1](#0-0) [2](#0-1) [3](#0-2) 

`repository_owner` is computed from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. In Rails, `ActionController::Base#params` is built by deep-merging query-string parameters with body parameters (`query_parameters.deep_merge(request_parameters)`), so any key that is absent from the JSON body but present in the query string still shows up in `params`. Meanwhile, `verify_signature` validates `request.headers['X-Hub-Signature']` strictly against `request.raw_post` (the body bytes only — GitHub's HMAC spec never covers the query string), and `create` re-derives the actually-processed payload via `JSON.parse(request.raw_post)` — body only, no query merge: [4](#0-3) 

and the selected `GitHubApp` used for that verification is looked up via `Shipit.github(organization: repository_owner)`: [5](#0-4) [6](#0-5) 

Handlers that actually take action key off the body's `repository.full_name` / `organization` fields only, independent of `repository_owner`: [7](#0-6) [8](#0-7) [9](#0-8) 

## Analog to the report

The externally reported bug is a class of "value used for gating/decision logic isn't actually validated/bound over the range/scope the code assumes." The Shipit analog is the same shape applied to authorization scope: **the organization whose secret authenticates the request** (`repository_owner`, resolvable via a query-string field not covered by the signature) **is not bound to the organization/repository whose event is actually dispatched and acted upon** (parsed purely from the signed raw body). This is exactly the disallowed-binding class "an organization that authenticated versus the repository that is written."

## Exploit path

In a multi-org Shipit deployment (`github:` keyed by organization, as documented), an attacker who legitimately controls their own GitHub App/organization ("org-attacker", with a real `webhook_secret` they know) can:

1. Build a JSON body whose `repository.full_name` (and other fields the handlers use) reference a *victim* organization/repository/stack hosted on the same Shipit instance, while omitting/mismatching the `repository.owner.login` / `organization.login` keys.
2. Compute a valid `X-Hub-Signature` for that exact body using their own `org-attacker` webhook secret.
3. POST to `/webhooks` with a query string like `?repository[owner][login]=org-attacker` (or `?organization[login]=org-attacker`).

`verify_signature` computes `repository_owner` from the deep-merged `params` (picks up `org-attacker` from the query string), calls `Shipit.github(organization: 'org-attacker')`, and the HMAC check succeeds because the attacker legitimately knows that secret and signed the exact raw body. `create` then re-parses `request.raw_post` (body only) and dispatches to `Shipit::Webhooks.for_event(event)` handlers using the victim's `repository.full_name`, e.g. triggering `PushHandler#process` → `stack.sync_github(expected_head_sha:)` for the victim stack, or a `membership` event manipulating `Team`/`Membership` records tied to the victim org.

This produces webhook-driven state changes (sync triggers, membership changes, review-stack archive/unarchive, pull_request-driven provisioning) against a repository/organization the request was never actually authenticated for — crossing the "verified organization" vs "written repository" trust boundary with no privileged credentials of the victim required.

### Title
Webhook signature verification selects the authenticating organization from unsigned query parameters, decoupling it from the repository actually acted upon - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#repository_owner` reads the organization used to pick the verifying `GitHubApp`/`webhook_secret` from Rails' merged `params` (query string + body), while `X-Hub-Signature` only covers the raw request body and the `create` action re-parses only the raw body for actual event dispatch. An attacker who owns a legitimately configured organization on the same multi-tenant Shipit instance can supply a validly-signed body targeting a different, victim organization's repository/stack by exploiting the query-string-vs-body mismatch used for organization selection.

### Finding Description
`verify_signature` derives `repository_owner` via `params.dig('repository','owner','login') || params.dig('organization','login')` [3](#0-2)  and uses it solely to pick which `GitHubApp` config verifies the HMAC [10](#0-9) . Since `params` merges query-string parameters into the body parameters, an attacker can inject a `repository[owner][login]` (or `organization[login]`) query parameter that is never part of `request.raw_post`, and therefore never covered by the signature that `verify_webhook_signature` checks against `request.raw_post` [6](#0-5) . The subsequent `create` action ignores query parameters entirely and dispatches handlers using only the JSON body [4](#0-3) , where handlers resolve the acted-upon repository purely from `payload.dig('repository','full_name')` [7](#0-6) . The organization used to authenticate the request is therefore not bound to the repository/organization the event is applied to.

### Impact Explanation
This allows a forged webhook event, signed with an attacker-controlled organization's own valid secret, to be dispatched against a different organization's repository/stack — driving unauthorized `sync_github` calls, `Team`/`Membership` mutations, or review-stack provisioning/archiving for that victim stack, without ever knowing the victim's real webhook secret. This is a cross-repository/cross-organization authorization bypass through the webhook ingestion path.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (documented and supported configuration) and requires the attacker to control at least one legitimately configured organization on the instance (e.g., a self-service or open-signup deployment, or one where multiple customer orgs share one Shipit instance). Given that this is an explicitly documented supported topology, the precondition is realistic.

### Recommendation
Derive `repository_owner` (and any value used to select the verifying secret) exclusively from the parsed raw body (the same `JSON.parse(request.raw_post)` used in `create`), never from `ActionController::Parameters`/query string. Additionally, after verification, assert that the organization whose secret verified the signature matches the organization owning the repository referenced in the body before dispatching to handlers.

### Proof of Concept
1. Attacker registers/controls `org-attacker` on the shared Shipit instance with a known `webhook_secret`.
2. Attacker crafts JSON body: `{"ref": "refs/heads/master", "after": "<sha>", "repository": {"full_name": "victim-org/victim-repo"}}` (no `owner` key).
3. Attacker computes `sha1=HMAC(org-attacker secret, body)`.
4. POST `/webhooks?organization[login]=org-attacker` with header `X-Github-Event: push`, `X-Hub-Signature: sha1=<computed>`, body from step 2.
5. `verify_signature` resolves `repository_owner` to `org-attacker` (from query), verifies successfully against attacker's own secret.
6. `create` dispatches `PushHandler` using the body's `repository.full_name = victim-org/victim-repo`, triggering `stack.sync_github` for the victim's stack.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-16)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit.rb (L170-181)
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

**File:** app/models/shipit/team.rb (L10-16)
```ruby
    has_many :github_hooks,
             -> { where(event: REQUIRED_HOOKS) },
             foreign_key: :organization,
             primary_key: :organization,
             class_name: 'GithubHook::Organization',
             inverse_of: false

```
