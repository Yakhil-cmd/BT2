Found the critical mismatch: `WebhooksController#verify_signature` selects the GitHub App/secret to verify against using `repository_owner` (`params.dig('repository','owner','login')` or `params.dig('organization','login')`), while `Handler#stacks` (used by `PushHandler`, `StatusHandler`, etc.) resolves the target repository/stack using an entirely different, unrelated payload field: `payload.dig('repository','full_name')`. These two lookups are never cross-checked against each other.

### Title
Webhook signature is verified against the organization derived from one payload field while the stack write targets a repository derived from a different, unchecked field - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
In a multi-organization Shipit deployment (`config/secrets.yml` with per-organization `github:` blocks, as documented in `docs/setup.md` and exercised by `test/dummy/config/secrets_double_github_app.yml`), each organization has its own `webhook_secret`. `WebhooksController#verify_signature` picks which organization's secret to verify the HMAC against using `repository_owner`, which reads `params.dig('repository','owner','login')` with a fallback to `params.dig('organization','login')`. [1](#0-0) 

However, the actual write target — which `Stack`/`Repository` gets synced — is computed later, independently, by `Handler#repository_name`/`#stacks`, which reads `payload.dig('repository', 'full_name')`: [2](#0-1) 

Because `verify_signature` never confirms that `repository.full_name`'s owner segment matches the `repository.owner.login`/`organization.login` field it used to select the secret, an org-B holder of a valid webhook secret (a legitimate, low-privilege GitHub App/organization admin — not a Shipit-privileged user) can craft a body whose `repository.owner.login` is `org-b` (so the signature check passes with org‑B's own secret) but whose `repository.full_name` is `org-a/some-repo`. Nothing recomputes the org from `full_name` for the actual write path.

### Finding Description
The binding that should hold is:
`organization used to verify the signature == organization actually written to (derived from repository.full_name)`.

Before the fix: `verify_signature` authenticates using `repository_owner` (from `repository.owner.login` or `organization.login`), but `PushHandler`/`StatusHandler`/etc. use `repository.full_name` split by `Repository.from_github_repo_name` to find the `Stack` to mutate. These are two separate reads of the same JSON body that are not cross-validated. An attacker who legitimately controls (or has been issued) a webhook secret for their own GitHub organization ("org-b") can therefore forge a signed payload where the `owner.login` fields used for auth say `org-b`, but the `full_name` field used for dispatch says `org-a/some-repo`, causing Shipit to run a `GithubSyncJob`/status update against a stack that belongs to a different organization than the one whose credentials actually authorized the request.

### Impact Explanation
This breaks the intended "authenticated organization" ⇔ "written repository" binding, enabling **cross-repository/cross-organization writes**: an attacker with only their own webhook secret can trigger `GithubSyncJob` (which fetches and appends commits, potentially deploying) against a stack whose repository belongs to another tenant organization configured in the same Shipit instance. This is squarely in the Critical impact bucket ("cross-repository writes, or an unauthorized deploy").

### Likelihood Explanation
This requires a multi-org Shipit deployment (the documented `github:` per-organization secrets schema), and requires the attacker to control a legitimate webhook secret for at least one configured organization (e.g., because they administer that org's GitHub App, which is a much lower privilege bar than Shipit admin access, an `ApiClient` token, or GITHUB_TOKEN access). No Shipit session or API token is required — only network access to `POST /webhooks` with a body they can freely construct and self-sign.

### Recommendation
In `WebhooksController#verify_signature`, after computing `repository_owner`, also derive the owner segment from `params.dig('repository', 'full_name')` and require them to match before accepting the signature; alternatively, have `Handler#stacks` re-verify that the resolved `Stack`'s repository owner matches the organization whose secret verified the request, rejecting the webhook otherwise.

### Proof of Concept
1. Shipit is configured with `secrets.yml` `github:` block containing two orgs, `org-a` and `org-b`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. Attacker administers the GitHub App installed for `org-b` and thus knows `org-b`'s `webhook_secret`.
3. Attacker crafts a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha that exists on org-a/some-repo>",
     "repository": {
       "owner": { "login": "org-b" },
       "full_name": "org-a/some-repo"
     }
   }
   ```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(org_b_webhook_secret, body)>` and POSTs to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` calls `Shipit.github(organization: 'org-b')` and verifies successfully using org-b's secret. [3](#0-2) 
6. `PushHandler#stacks` resolves `Repository.from_github_repo_name('org-a/some-repo')` from `full_name` and calls `stack.sync_github(...)`, mutating a stack belonging to `org-a`, even though authentication was performed against `org-b`'s secret. [2](#0-1) [4](#0-3) 

**Note on confidence**: I was unable to execute this PoC in the codebase (no terminal access in ask-only mode); the analysis is based on static reading of `webhooks_controller.rb`, `handler.rb`, `push_handler.rb`, and `lib/shipit.rb`'s multi-org `github_app_config` support. This should be validated against the live behavior of `GithubOrganizationUnknown` handling and any additional cross-checks that might exist elsewhere in the request pipeline that were not surfaced by the search.

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
