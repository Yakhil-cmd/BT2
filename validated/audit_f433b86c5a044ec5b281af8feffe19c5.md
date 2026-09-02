This confirms the vulnerability. `Shipit.github(organization:)` looks up config by whatever org name the payload's `repository.owner.login` (or `organization.login`) contains, and only verifies the HMAC signature against *that* org's `webhook_secret` — it never checks that this org actually owns the repository named elsewhere in the same JSON body (`repository.full_name`). [1](#0-0) [2](#0-1) [3](#0-2) 

Downstream, `Handler#repository_name` reads `payload.dig('repository', 'full_name')` from the very same unsigned/attacker-controlled body and `Handler#stacks` resolves it via `Repository.from_github_repo_name` with no further ownership check. [4](#0-3)  `PushHandler#process` then calls `stack.sync_github(expected_head_sha: params.after)` on whatever stacks that lookup returns. [5](#0-4) 

### Title
Cross-tenant deploy trigger via webhook signature/repository-name mismatch - (File: app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a webhook using the `webhook_secret` of the organization named at `repository.owner.login`, but `Handler#repository_name` / `Handler#stacks` resolve the target stacks from `repository.full_name` in the same unverified JSON body without checking it belongs to that same verified organization. An attacker who legitimately owns org-X (and thus its `webhook_secret`) can sign a payload whose `repository.full_name` points at `org-Y/target-repo`, causing Shipit to run `PushHandler#process` against org-Y's real stack.

### Finding Description
The broken binding: `repository.owner.login` (used by `verify_signature` to select the `webhook_secret`) should equal the owner of `repository.full_name` (used by `Handler#stacks`) — but nothing enforces this equality.

- `verify_signature` picks `Shipit.github(organization: repository_owner)` where `repository_owner` is `params.dig('repository','owner','login')`, and calls `verify_webhook_signature` against `request.raw_post` using that org's configured secret. [6](#0-5) [2](#0-1) 
- `Handler#initialize` re-parses the identical raw body via `create` and passes it to the matching event handler. [7](#0-6) 
- `Handler#repository_name` reads `payload.dig('repository', 'full_name')` — a *different* field than the one used for signature scoping — with no cross-check against `repository.owner.login`. [8](#0-7) 
- `Handler#stacks` resolves `Repository.from_github_repo_name(repository_name)` and returns its `stacks`. [9](#0-8) 
- `PushHandler#process` iterates matching stacks and calls `stack.sync_github(expected_head_sha: params.after)`. [5](#0-4) 

Since GitHub App webhook secrets are configured per-organization via `Shipit.github_app_config` keyed strictly on org name, having a valid secret for org-X says nothing about org-Y; yet the code treats "signature verified" as blanket authorization for whatever repo name appears in `full_name`. [10](#0-9) 

Attack: attacker creates org-X on GitHub, installs/configures a Shipit GitHub App for org-X (obtaining a legitimate `webhook_secret` for org-X only), crafts a `push` event JSON body with `repository.owner.login = "org-X"` but `repository.full_name = "org-Y/target-repo"`, signs it with org-X's secret in `X-Hub-Signature`, and POSTs to `/webhooks`. `verify_signature` passes because the signature matches org-X's secret and org-X's raw body. `PushHandler` then finds and syncs org-Y's real, unrelated stack.

Existing guards don't stop this: `drop_unhandled_event` only checks the event type exists; `ExplicitParameters` schema for `PushHandler` only requires `ref` and `after`, not repository ownership consistency; no code path compares `repository.owner.login` to the owner portion of `repository.full_name`.

### Impact Explanation
An attacker with no relationship to org-Y can force `Stack#sync_github` to run against org-Y's stack, triggering a GitHub sync/deploy pipeline action for a repository they don't own and never signed for — this is a cross-tenant action derived from another party's unauthenticated payload content, matching the "payload for one repository mutating another's stack" Critical category. This is repeatable for any target repo whose `owner/name` the attacker can guess/know, as long as the attacker controls any org configured in Shipit (their own).

### Likelihood Explanation
Requires the multi-org GitHub App config mode (i.e., `Shipit.github_default_organization` non-nil, meaning `secrets.github` is keyed by multiple org names) and that the attacker's own org (org-X) is registered/onboarded in that Shipit instance with its own webhook secret — a plausible deployment pattern for multi-tenant Shipit instances serving several orgs. Given that precondition, attacker cost is trivial: sign one JSON body with a secret they legitimately possess.

### Recommendation
In `WebhooksController` or `Handler`, verify that `repository.full_name`'s owner segment matches the `repository_owner` used to select/validate the webhook secret before dispatching to any handler (e.g., reject if `repository.full_name.split('/').first.casecmp(repository_owner) != 0`).

### Proof of Concept
Minitest plan (extends `test/controllers/webhooks_controller_test.rb` pattern):
1. Configure two orgs in test secrets, `org-x` and `org-y`, each with distinct `webhook_secret`.
2. Build a `push` payload with `repository.owner.login = "org-x"` and `repository.full_name = "org-y/target-repo"`, where `org-y/target-repo` has an existing `Stack` fixture.
3. Sign the raw JSON with org-x's `webhook_secret` and set `X-Hub-Signature`.
4. POST to `/webhooks` with `X-Github-Event: push`.
5. Assert (via Mocha `Stack.any_instance.expects(:sync_github)` or on the specific fixture stack) that `sync_github` is invoked on org-y's stack — proving the binding `repository_owner == owner(repository.full_name)` is not enforced despite a valid signature only for org-x.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
