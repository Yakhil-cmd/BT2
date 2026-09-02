This is the exact binding break the rules describe: the organization whose webhook secret authenticates the HMAC is derived from `repository.owner.login` (or the fallback `organization.login`), while the repository that GitHub events are actually applied to is derived independently from `repository.full_name` inside each `Handler`.

### Title
Webhook signature verified against attacker-chosen organization while events are applied to a different repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification purely from attacker-controlled JSON fields (`repository.owner.login`, falling back to `organization.login`), but `Handler#stacks`/`Handler#repository_name` (and thus every write performed by a handler, e.g. `PushHandler`) resolves the target repository from the separate `repository.full_name` field in the same, single signature-covered payload. [1](#0-0) [2](#0-1) 

### Finding Description
`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` (or `organization.login`) and fetches the corresponding `Shipit.github(organization: repository_owner)` app config in order to validate `X-Hub-Signature` against that organization's `webhook_secret`: [3](#0-2) 

Once the signature check passes, `WebhooksController#create` dispatches the entire raw payload to `Shipit::Webhooks.for_event(event)` handlers, e.g. `PushHandler`, which resolves the actual repository/stacks to mutate using `repository.full_name` via `Repository.from_github_repo_name`: [4](#0-3) [5](#0-4) 

The binding that should hold is: `organization used to verify signature == owner(repository.full_name) used to act`. Because both fields are attacker-supplied inside the same JSON body and the signature covers the raw bytes but not a semantic constraint tying `repository.owner.login` to `repository.full_name`, this reduces to a self-consistency check on attacker-controlled data, not a real cross-check. Any operator who knows (or has been given/rotated) the webhook secret for **one** GitHub organization/App instance they legitimately administer in this Shipit install can forge a payload where `repository.owner.login` is set to that organization (satisfying `verify_signature`) while `repository.full_name` names any repository/owner pair that has a `Repository`/`Stack` record already configured in this Shipit instance, causing `PushHandler` (and other handlers keyed by `repository.full_name`, e.g. `pull_request` handlers under `app/models/shipit/webhooks/handlers/pull_request/`) to act on a stack belonging to a repository outside that organization.

This is a direct analog of the report's core defect: a value that is authenticated (here, "which organization's secret verified this request") is not the same value that downstream code trusts to decide "which resource does this request apply to" (here, `repository.full_name`), mirroring the yield contract's `totalSupply`/`balanceOf` mismatch where the checked state diverges from the acted-upon state.

### Impact Explanation
An attacker who legitimately controls (or has leaked/rotated) the webhook secret for organization A, but has no GitHub write access to organization B's repositories, can submit a forged `X-Hub-Signature` payload naming `repository.owner.login: "A"` and `repository.full_name: "B/some-repo"`. If Shipit hosts a stack for `B/some-repo`, the push handler will call `stack.sync_github(expected_head_sha: params.after)` for that foreign stack using an attacker-chosen `after` SHA, enqueuing sync/deploy-eligible state changes for a repository the attacker does not control on GitHub. Depending on continuous-deployment configuration this can trigger unauthorized deploy pipelines against a cross-organization repository, i.e. writes to a repository the attacker's credentials never authorized — matching the Critical "cross-repository writes / unauthorized deploy" bar.

### Likelihood Explanation
Exploitability requires the attacker to possess a valid webhook secret for at least one organization configured in this Shipit instance (a legitimate but lower-trust integration) and for a targeted stack for a different repository to already exist in the same instance — a realistic multi-tenant Shipit deployment scenario, since `Shipit.github(organization:)` supports per-organization configuration and nothing in `verify_signature` or the handlers cross-checks organization identity against the acted-upon `full_name`.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), enforce that the organization derived for signature verification matches the owner segment of `repository.full_name` used by the handler before dispatching, e.g. reject the request if `repository_owner != payload.dig('repository', 'full_name').split('/').first`, or have handlers exclusively use the same field already validated as the signing organization.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` (attacker controls its webhook secret) and `org-b` (hosts a real Stack for `org-b/victim-repo`, attacker has no GitHub access).
2. Craft a `push` webhook JSON body: `{"ref": "refs/heads/main", "after": "<attacker-chosen sha>", "repository": {"full_name": "org-b/victim-repo", "owner": {"login": "org-a"}}}`.
3. Sign the raw body with `org-a`'s `webhook_secret` and set `X-Hub-Signature`.
4. POST to `/webhooks` with `X-Github-Event: push`; `verify_signature` resolves `repository_owner` = `org-a`, validates successfully against `org-a`'s secret.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("org-b/victim-repo")`, finds the real `org-b` stack, and calls `sync_github(expected_head_sha: "<attacker-chosen sha>")` on it despite the attacker never having GitHub credentials for `org-b`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
