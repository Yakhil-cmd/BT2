### Title
Cross-repository write via organization/repository binding mismatch in webhook signature verification - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's webhook secret to use for HMAC verification from `repository.owner.login` (with a fallback to `organization.login`), while the handlers that actually mutate state (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, the `PullRequest::*Handler`s) resolve the target `Repository`/`Stack` from the independent `repository.full_name` field. Because both fields live inside the same attacker-supplied JSON body that is being signed, an attacker who knows the webhook secret for *any* one organization configured in Shipit can forge a payload whose `repository.owner.login` matches that known-secret organization while `repository.full_name` points at a completely different, victim-owned repository tracked by the same Shipit instance.

### Finding Description
Signature verification is performed like this: [1](#0-0) [2](#0-1) 

`repository_owner` is derived from `params.dig('repository', 'owner', 'login')` (or the top-level `organization.login` as a fallback). That value is used to fetch the per-organization `GitHubApp` config and its `webhook_secret`: [3](#0-2) 

Meanwhile, the code path that actually performs the write — resolving which `Repository`/`Stack` records get mutated — uses a *different* field of the same JSON body, `repository.full_name`, completely independent of `repository.owner.login`: [4](#0-3) [5](#0-4) 

`PushHandler`, for example, uses this `stacks` scope (bound to `repository.full_name`) to enqueue sync jobs with no further authorization check tying the sync target back to the verified organization: [6](#0-5) 

Because a legitimate GitHub webhook always keeps `repository.owner.login` and `repository.full_name`'s owner segment consistent (GitHub itself generates both), this mismatch is normally never observable. But the entire JSON body here is attacker-controlled input being signed by the attacker — the signature only proves the request body was signed with *some* organization's secret, not that the `repository.owner.login` field is consistent with the `repository.full_name` field used to select the write target.

This breaks the intended binding: **organization that authenticated (`repository.owner.login` → `webhook_secret` used to verify HMAC) ≠ repository that is written (`repository.full_name` → `Repository.from_github_repo_name` → `Stack`)**. This is structurally the same bug class as the SmartSession report: a verification/authorization step (`verify_webhook_signature`) is bound to one piece of data (`repository.owner.login`), while the actual privileged action (mutating stacks/commits/PR state under `repository.full_name`) is driven by a separate, unchecked piece of data in the same payload, allowing the check to pass without covering the action actually taken.

### Impact Explanation
This is a cross-repository write: an attacker who is legitimately configured in Shipit for organization A (i.e., they know/control the `webhook_secret` value Shipit uses for org A — e.g., because they are the organization admin who installed/configured the app for their own org) can forge signed webhook events (`push`, `status`, `check_suite`, `pull_request`) that are routed by `repository.full_name` to any other repository tracked by the same Shipit instance, regardless of which organization owns it. This can trigger unintended `GithubSyncJob` syncs, fake commit statuses, review-stack provisioning/archival, or PR state changes against a victim repository the attacker does not control — an unauthorized cross-tenant write, which maps to the "cross-repository writes" Critical category.

### Likelihood Explanation
Requires the attacker to already control the webhook secret for at least one organization onboarded to the Shipit instance (multi-tenant Shipit deployments are supported via `Shipit.github(organization:)`/per-org config). This is a plausible unprivileged-attacker scenario in any Shipit deployment serving multiple GitHub organizations where each organization administers its own secret, since one tenant's legitimate access should not extend to writing another tenant's repositories. No GitHub App private key, session, or `ApiClient` token is needed — only knowledge of one organization's `webhook_secret`, and the target repository's public `owner/name`.

### Recommendation
Bind signature verification to the same repository identity used for the write path: require `repository.owner.login` to match the owner segment of `repository.full_name` before proceeding, or better, verify the signature using the secret associated with the repository actually being resolved by the handler (`repository.full_name`) rather than a separately-supplied `repository.owner.login`/`organization.login` field. Reject the webhook if these two fields disagree.

### Proof of Concept
1. Shipit is configured with two organizations, `orgA` (attacker-administered, secret known to attacker) and `orgB` (victim, repo `orgB/victim-repo` tracked in Shipit, tracked stack exists for branch `master`).
2. Attacker crafts a `push` webhook JSON body:
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
3. Attacker computes `X-Hub-Signature` using `orgA`'s known `webhook_secret` over the raw body, per `sign`/`verify_webhook_signature` logic: [3](#0-2) 
4. `WebhooksController#verify_signature` resolves `repository_owner == "orgA"`, fetches orgA's `GitHubApp`, and successfully verifies the signature against orgA's secret: [7](#0-6) 
5. `PushHandler#process` resolves the target stacks via `repository.full_name == "orgB/victim-repo"`, entirely bypassing any dependency on `orgA`, and enqueues `GithubSyncJob` for `orgB/victim-repo`'s stack: [4](#0-3) [6](#0-5) 

Note: I was unable to fully verify from the index how many organizations a single Shipit deployment typically configures or the exact structure of the multi-org `github` config lookup (`lib/shipit.rb`'s `Shipit.github` method contents were not retrievable within tool-call limits), so the degree to which this is a true multi-tenant deployment concern versus a single-organization deployment (where this bug would be unreachable, since there'd be only one secret) could not be fully confirmed from the available index. If your deployment only configures a single GitHub organization/secret, this specific analog does not apply.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
