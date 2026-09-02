### Title
Cross-organization webhook forgery via mismatched `repository.owner.login` and `repository.full_name` fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the GitHub App configuration (and thus the HMAC secret used for signature verification) based on `repository_owner`, taken from `payload.dig('repository', 'owner', 'login')` (falling back to `payload.dig('organization', 'login')`). Separately, every `Webhooks::Handlers::Handler` subclass resolves the actual target of the webhook (the `Repository`/`Stack` acted upon) using a different, independent JSON field: `payload.dig('repository', 'full_name')`. Nothing in the code enforces that `repository.owner.login` is consistent with the owner segment of `repository.full_name`. [1](#0-0) [2](#0-1) 

### Finding Description
Shipit supports hosting multiple GitHub organizations from one instance, each with its own GitHub App configuration and its own `webhook_secret`, selected per-request via `Shipit.github(organization: ...)`: [3](#0-2) 

The webhook signature check only validates that the raw HTTP body was signed with the secret belonging to whichever organization `repository_owner` names — it never checks that this organization actually owns the repository referenced elsewhere in the same payload: [4](#0-3) 

Meanwhile, the handlers that perform the actual side effects (looking up stacks, creating commit statuses, closing review stacks, syncing branches, etc.) resolve the target repository purely from `repository.full_name`: [2](#0-1) [5](#0-4) [6](#0-5) 

Because a JSON webhook body is entirely attacker-controlled once its signature is valid, an attacker who legitimately owns/administers **their own** GitHub organization onboarded to the same Shipit instance (with their own, self-controlled `webhook_secret` for that org) can:
1. Set `repository.owner.login` (and/or top-level `organization.login`) to their own org name — so `verify_signature` selects and validates against their own known secret.
2. Set `repository.full_name` to `"victim-org/victim-repo"` — a repository belonging to a different organization also configured on the same Shipit instance.
3. Sign the resulting JSON body with their own secret and POST it to `/webhooks`.

The signature check passes (it only proves the attacker's own org secret matches), but the handler dispatch acts on the victim repository named in `full_name`, breaking the equality that the report's bug class targets: *organization that authenticated == repository that is written*.

### Impact Explanation
This lets an unprivileged-but-onboarded attacker (who administers one org on a multi-tenant Shipit instance) forge GitHub events for a *different* org's repositories/stacks without ever needing that victim org's `webhook_secret`, GitHub App key, or Shipit session:
- `status` events let the attacker fabricate a `Shipit::Status` (arbitrary `state`, `description`, `target_url`) for arbitrary commits of the victim's stacks, which can mark commits as CI-green and unblock/trigger an unauthorized deploy.
- `push` events can force `GithubSyncJob` to run against the victim stack repeatedly (mostly a resync using real GitHub data via Shipit's own credentials, so limited direct write impact there).
- `pull_request` (closed/opened/labeled/etc.) events can archive, spawn, or otherwise mutate the victim's review stacks.

This crosses the "unauthorized deploy" / cross-repository write bar defined in scope, though it is only reachable in deployments that configure multiple GitHub organizations under one Shipit instance (the single-org backward-compatible config path in `Shipit.github_default_organization` does not have this ambiguity in the same way, since there is only one secret to check against regardless of the payload's claimed owner).

### Likelihood Explanation
Requires: (a) the Shipit instance to be configured for multiple GitHub organizations, (b) the attacker to control at least one of those onboarded orgs (their own `webhook_secret`, which they legitimately possess since it's their own org's app config — not a stolen secret), and (c) a target stack from a different onboarded org to attack. This is a realistic but non-trivial precondition; it is plausible for shared/self-hosted Shipit deployments serving several partner orgs, less so for single-org deployments (the common case).

### Recommendation
In `WebhooksController#verify_signature` and/or in `Webhooks::Handlers::Handler#stacks`/`#repository_name`, cross-validate that the organization selected for signature verification (`repository_owner`) matches the owner segment of `repository.full_name` (and of `organization.login` if present) before dispatching to handlers. Reject the webhook (422) on mismatch.

### Proof of Concept
1. Configure Shipit with two orgs, `attacker-org` (secret known to attacker) and `victim-org` (unrelated), each with its own `Stack`.
2. Attacker crafts a `status` webhook payload:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "target_url": "https://ci.example.com/fake",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and validates successfully against the attacker's own secret [7](#0-6) .
5. `Webhooks.for_event("status")` handler resolves the target repository/stacks from `repository.full_name = "victim-org/victim-repo"` [2](#0-1) , and creates a forged `Status` record on the victim's commit — without ever needing `victim-org`'s webhook secret.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
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
