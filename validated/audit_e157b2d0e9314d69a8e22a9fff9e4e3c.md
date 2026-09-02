### Title
Webhook signature verified against `repository.owner.login` while the acted-upon repository is read from an independently-controlled `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) straight out of the still-unauthenticated JSON body. All downstream handlers, however, resolve the target repository/stack from a *different* field of the same body, `repository.full_name` ` [1](#0-0) `. On real GitHub deliveries these two fields are always consistent, but Shipit never cross-checks them against each other, so the binding "organization whose secret authenticated the request" == "repository that gets written to" is not actually enforced by the signature.

### Finding Description
`verify_signature` reads the organization used for secret lookup from the payload before the signature is checked: [2](#0-1) [3](#0-2) 

`Shipit.github(organization:)` resolves a per-organization config (and secret) via `github_app_config`, which is a documented, supported multi-tenant configuration mode [4](#0-3) . In this mode different organizations onboarded onto the same Shipit instance can have distinct `webhook_secret` values.

Once `verify_webhook_signature` passes (HMAC over the raw body using whichever org's secret was selected), the actual event handler resolves the stack to act on using a *different* JSON key entirely, `repository.full_name`, via `Handler#repository_name`/`#stacks` [1](#0-0) , e.g. `PushHandler#process` calling `stack.sync_github(expected_head_sha: params.after)` for every matching stack [5](#0-4) .

Because HMAC verification only proves "this byte string was signed with organization X's secret," and X is picked from an unauthenticated field, nothing stops an attacker who legitimately controls (or has leaked/rotated) organization X's `webhook_secret` from crafting a JSON body where `repository.owner.login` == "X" (so X's secret is selected and validates) while `repository.full_name` == "Y/victim-repo" for a completely unrelated organization/repository Y that is also configured in the same Shipit instance. The equality the engine implicitly relies on — organization-that-authenticated == organization/repository-that-is-written — is never checked in code; it is only true by convention on genuine GitHub payloads, not enforced by Shipit.

### Impact Explanation
If exploited, this allows an attacker holding a valid webhook secret for their own onboarded organization to push forged `push`, `status`, `check_suite`, or `membership` events that are attributed to and acted on for a completely different organization's repositories/stacks in the same Shipit instance — e.g., triggering `GithubSyncJob`/`sync_github` on another org's stack, creating bogus commit `Status`es, or manipulating `Membership`/`Team` records cross-organization. This is a cross-repository/cross-organization write achieved without holding that organization's own secret, matching the "cross-repository writes" Critical impact category.

### Likelihood Explanation
Exploitability requires: (1) Shipit configured in the multi-organization credentials mode (`github_app_config`/per-org secrets) rather than the single global-secret backward-compatible mode; (2) the attacker's own organization is legitimately onboarded to that same Shipit instance (so it is not "no credential" at all — the attacker does hold a real, valid webhook secret, just for a different tenant than the one being written to). This is a realistic multi-tenant deployment scenario the engine explicitly supports, but I could not verify from the indexed code whether any additional validation exists elsewhere (e.g., in `GithubSyncJob` or `Repository.from_github_repo_name`) that cross-checks the claimed owner against the resolved repository's actual owner — this would need to be confirmed by reading `app/jobs/shipit/github_sync_job.rb` and `app/models/shipit/repository.rb` in full, which were only partially surfaced by search.

### Recommendation
After signature verification succeeds, re-derive the organization from the same field used for repository/stack resolution (`repository.full_name`'s owner segment, or `organization.login` used consistently) and assert it matches the organization whose secret validated the signature. Reject the webhook (422) if `repository.owner.login`/`organization.login` used for secret selection does not match the owner segment of `repository.full_name` used by handlers.

### Proof of Concept
1. Configure Shipit in multi-org mode with `github_app_config` entries for `orgA` (attacker-controlled, secret known to attacker) and `orgB` (victim, has a stack tracking `orgB/victim-repo`).
2. Attacker crafts a `push` webhook body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, body)>` using their own known `orgA` secret.
4. POST to `/webhooks` with `X-Github-Event: push`. `verify_signature` calls `Shipit.github(organization: "orgA")`, verifies successfully against `orgA`'s secret.
5. `PushHandler#process` resolves `repository_name` as `orgB/victim-repo` and enqueues sync/deploy-affecting work for `orgB`'s stack, even though the request was never signed with `orgB`'s secret.

Note: I was unable to fully verify all downstream consumers of `repository_name`/`stacks` (e.g., `Repository.from_github_repo_name`, `GithubSyncJob`) for any independent owner cross-check, since only partial contents of those files were retrieved via search; a full read of `app/models/shipit/repository.rb` and `app/jobs/shipit/github_sync_job.rb` would be needed to conclusively rule out an existing mitigation.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
