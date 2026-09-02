## Title
Webhook signature verified against `repository.owner.login`, but handlers act on the unrelated `repository.full_name` from the same untrusted payload — cross-organization/cross-repository write - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate the HMAC signature against using a field it reads directly out of the **unverified** JSON body (`repository.owner.login`), before the signature has been checked. Once the signature passes, the same request body is dispatched to event handlers that instead trust a *different* field of that very same payload — `repository.full_name` — to decide which `Stack`/`Repository` record to act on. In Shipit's multi-organization configuration schema (`config/secrets.*.yml`, each org keyed under `github:`), an attacker who legitimately controls one configured organization (and therefore knows *that* organization's `webhook_secret`) can forge a payload whose `owner.login` matches their own org (so it authenticates) while `repository.full_name` points at a completely different tracked repository/organization, causing Shipit to act on a repo the attacker does not control.

### Finding Description
`verify_signature` picks the `GitHubApp`/secret using a value taken straight from the raw, not-yet-authenticated body: [1](#0-0) 

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
...
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

`Shipit.github(organization:)` resolves this string to a per-organization config entry (each with its own `webhook_secret`) in the multi-org schema: [2](#0-1) 

Once `verify_webhook_signature` succeeds (HMAC computed with **that org's** secret over the full raw body), `create` dispatches the entire, attacker-fully-controlled payload to the matching event handler: [3](#0-2) 

Handlers, however, never re-check `repository.owner.login`; they resolve the target repository/stack purely from `repository.full_name`, a sibling field inside the same payload: [4](#0-3) 

For example `PushHandler` finds and syncs stacks for whatever `repository.full_name` says: [5](#0-4) 

and pull-request handlers resolve `repository` (and cascade to review-stack archive/unarchive/create actions) the same way: [6](#0-5) 

Because the HMAC only guarantees the request body wasn't tampered with in transit — it says nothing about which secret was legitimately used to sign it — an attacker who controls **any** organization configured on the Shipit instance (and thus knows that org's `webhook_secret`, e.g. because they administer the GitHub App/webhook for their own org) can compute a valid signature for a payload they author from scratch, in which `repository.owner.login` == their own org (to select their own secret at verification time) while `repository.full_name` == a different org/repo tracked by the same Shipit instance. The binding broken is:

`organization that authenticated (repository.owner.login, used to select webhook_secret) == repository that is written (repository.full_name, used by handlers)`

This equality is assumed but never enforced.

### Impact Explanation
This allows cross-repository/cross-organization writes without any legitimate access to the target repository: an attacker can trigger `GithubSyncJob` (and thus commit ingestion / status updates / potential auto-deploys via continuous delivery schedules) for stacks belonging to an organization/repository they do not own, or manipulate `PullRequest`/`ReviewStack` state (archive, unarchive, provisioning) for another team's repository, purely by knowing the webhook secret of any single organization onboarded to the shared Shipit instance. This matches the "cross-repository writes" / "unauthorized deploy" Critical impact class, since it breaks the trust boundary between organizations that are supposed to be isolated by per-org webhook secrets.

### Likelihood Explanation
Exploitability requires the attacker to know one organization's `webhook_secret` in a multi-org Shipit deployment — which is realistic since that secret is handed to org admins/CI systems for legitimate use, and is not meant to authorize actions against *other* organizations' repositories. No GitHub session, `ApiClient` token, or repository write access to the target repo is needed; only the ability to send an HTTP POST with a correctly-computed HMAC using a secret the attacker legitimately possesses for their own org.

### Recommendation
After `verify_webhook_signature` succeeds, re-validate that the repository actually referenced by the payload (`repository.full_name`) belongs to the same organization (`repository_owner`) whose secret was used to authenticate the request, and reject the webhook (422) if they don't match. Alternatively, look up the target `Repository`/`Stack` via the authenticated organization scope rather than trusting an unqualified `full_name` field from the payload.

### Proof of Concept
1. Shipit is configured with two organizations in `secrets.github`: `orgA` (attacker-controlled, webhook secret known to attacker) and `orgB` (contains a private/protected `Stack` the attacker wants to affect).
2. Attacker crafts a JSON body mimicking a GitHub `push` event:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "full_name": "orgB/private-repo",
    "owner": { "login": "orgA" }
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(orgA_webhook_secret, body)` using the secret they legitimately hold for `orgA`.
4. POST to `/github/webhooks` (or the engine's mounted webhooks path) with header `X-Github-Event: push` and the computed signature.
5. `verify_signature` calls `Shipit.github(organization: "orgA")`, which succeeds since the signature matches `orgA`'s secret.
6. `PushHandler` (via `Handler#repository_name` / `payload.dig('repository','full_name')`) resolves and syncs `orgB/private-repo`'s stacks, even though the authenticating organization was `orgA`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-59)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```
