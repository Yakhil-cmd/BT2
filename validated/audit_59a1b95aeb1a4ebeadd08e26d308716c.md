### Title
Webhook signature verification is bound to the payload's `repository.owner`/`organization` login while every event handler acts on an independently-controlled `repository.full_name` (or a bare commit `sha`), letting an attacker who controls one tracked organization's webhook secret forge status/push/PR events for any *other* organization's stack on the same Shipit instance - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to validate the HMAC signature against based on `repository.owner.login`/`organization.login` taken from the untrusted JSON body itself. [1](#0-0)  The org used to pick the secret is not cryptographically bound to the data the event handlers actually act on: `Handler#stacks`/`#repository_name` and `PushHandler`, the `PullRequest` handlers, and `StatusHandler` all resolve the target `Repository`/`Commit` from other independent fields of the same forgeable payload (`repository.full_name`, or in the `status` handler, a bare `sha` with no repository scoping at all). [2](#0-1) [3](#0-2) 

### Finding Description
Shipit supports multiple GitHub organizations being onboarded to a single instance, each with its own `webhook_secret` configured in `secrets.github.<org>.webhook_secret` [4](#0-3) . `Shipit.github(organization:)` looks up the `GitHubApp` (and its `webhook_secret`) purely by the organization key supplied by the caller. [5](#0-4) 

In `WebhooksController#verify_signature`, that organization key is derived directly from the incoming JSON body:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [6](#0-5) 

So the equality actually enforced by the signature check is:
`HMAC_valid_for(secret_of(payload["repository"]["owner"]["login"]))`

But the equality that matters for authorization — which stack/commit/repository gets mutated — is a *different* field pulled from the very same attacker-supplied JSON:
- `PushHandler`/PR handlers: `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))` [7](#0-6) [8](#0-7) 
- `StatusHandler`: `Commit.where(sha: params.sha)` — no repository/owner check whatsoever. [3](#0-2) 

Because `repository.owner.login` (used for signature selection) and `repository.full_name` / `sha` (used for the write) are two unrelated fields inside the same JSON body that the attacker fully controls, an attacker who legitimately controls (or has compromised) the webhook secret for **Organization A** (e.g. they administer a GitHub App/webhook that Org A configured, or they are simply the org admin who set up the app for their own tracked repo in Shipit) can craft a payload where:
- `repository.owner.login = "org-a"` (so the signature is computed/verified with Org A's secret, which the attacker knows), and
- `repository.full_name = "org-b/victim-repo"` or `sha = "<commit sha belonging to org-b's stack>"` (the actual target of the handler).

`Shipit.github(organization: "org-a")` returns Org A's `webhook_secret`, the HMAC check passes because the attacker signed with the secret they actually possess, and the request is accepted. The handler then acts on Org B's data using a field never covered by that verification.

### Impact Explanation
This breaks repository/organization isolation on any Shipit instance configured for multiple organizations (the documented multi-org config schema in `config/secrets.development.example.yml` and `lib/shipit.rb#github_organizations`). Concretely:
- Via the `status` event: the attacker can inject arbitrary commit statuses (`state: success`, forged `context`/`description`) for any commit `sha` in *any* other tracked repository, with zero scoping to their own repo. `StatusHandler` writes it straight into `Commit#create_status_from_github!` for every commit row matching that sha, cluster-wide. Commit statuses gate `required_statuses`/`blocking_statuses` used by `Stack`/`DeploySpec` to decide whether a commit is deployable, so this can force an unauthorized deploy to succeed on a repository the attacker has no access to, or block a legitimate deploy for another team. [9](#0-8) 
- Via the `push` event: `PushHandler` will enqueue `stack.sync_github(expected_head_sha:)` for Org B's stacks whose branch matches, causing Shipit to sync/deploy state for a repository the attacker doesn't control, using an `expected_head_sha` the attacker chose. [8](#0-7) 
- Via `pull_request` events: an attacker can create/close/archive review stacks belonging to Org B's repositories by forging `repository.full_name`. [10](#0-9) 

This is a cross-organization write into another tenant's deployment state/CI signal, satisfying the "unauthorized deploy/rollback" and "cross-repository writes" High/Critical impact bar.

### Likelihood Explanation
Medium-High for multi-org Shipit deployments: it requires only that the attacker be a legitimate (or compromised) admin of the GitHub App/webhook for **any one** organization tracked on the shared Shipit instance — not any credential, session, or write access to the victim organization/repository. No `ApiClient` token, GitHub App private key, or Shipit session is needed; only knowledge of one org's `webhook_secret`, which by design is held by that org's own GitHub App settings. Single-org deployments are not affected since there is only one secret/org to select from.

### Recommendation
Do not use attacker-supplied payload fields to select the verification secret and then trust a different, unrelated payload field for authorization. Concretely:
- After verifying the signature with the secret selected for `repository_owner`, re-derive and enforce that `repository.full_name`'s owner segment (and, for `status` events, the resolved `Commit`'s `stack.repository.owner`) matches the same `repository_owner`/organization that produced a valid signature, rejecting the event otherwise.
- In `Handlers::Handler` and `StatusHandler`, scope repository/commit lookups by the same organization identity that was cryptographically verified, not purely by attacker-controlled `full_name`/`sha`.
- Consider signing/binding the verified organization identity into the object passed to handlers (e.g. pass `repository_owner` alongside `params`) instead of re-parsing it from the untrusted body inside each handler.

### Proof of Concept
1. Shipit instance configured with two organizations in `secrets.github`: `org-a` and `org-b`, each with their own tracked stacks and their own `webhook_secret`. [11](#0-10) 
2. Attacker is the (legitimate) GitHub App admin for `org-a` and therefore knows `org-a`'s `webhook_secret`.
3. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<sha of a commit belonging to org-b/victim-repo tracked stack>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "org-a" }, "full_name": "org-a/some-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(org-a-webhook-secret, body)` and POSTs it to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#repository_owner` returns `"org-a"`; `Shipit.github(organization: "org-a")` returns org-a's `GitHubApp` and its secret; `verify_webhook_signature` succeeds because the attacker signed with the secret they actually hold. [12](#0-11) 
6. `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`, which runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — matching the commit in `org-b/victim-repo`'s stack purely by `sha`, with no relation to `org-a` at all — and writes a forged "success" status onto it, potentially unblocking a deploy on `org-b`'s stack. [3](#0-2)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** lib/shipit.rb (L190-200)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/commit.rb (L55-58)
```ruby
    scope :reachable, -> { where(detached: false) }

    delegate :broadcast_update, :github_repo_name, :hidden_statuses, :required_statuses, :blocking_statuses,
             :soft_failing_statuses, to: :stack
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
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
          end
```

**File:** config/secrets.development.example.yml (L18-29)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```
