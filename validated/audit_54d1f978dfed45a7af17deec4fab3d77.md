This confirms the vulnerability path. `WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to verify against using `repository_owner`, which is read directly from the untrusted, attacker-controlled JSON body (`params.dig('repository', 'owner', 'login')`). But the actual event handling in `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb`) looks up the target `Repository`/`Stack` using a **different** field from the same body — `payload.dig('repository', 'full_name')` — with no check that this repository's owner matches the `repository_owner` that was used to select the signing secret.

### Title
Webhook signature verified against attacker-chosen organization while the event is applied to an unrelated repository's stack - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
In multi-organization Shipit deployments (`config/secrets.yml` defining several GitHub orgs, each with its own `webhook_secret`), `WebhooksController#verify_signature` picks the HMAC secret to validate against based on `repository_owner`, computed from the unauthenticated request body itself (`params.dig('repository','owner','login')`). Once verification passes, `create` dispatches the same raw body to handlers (`app/models/shipit/webhooks/handlers/handler.rb`), which independently derive the target repository from `payload.dig('repository','full_name')`. Nothing enforces that the `owner.login` used for signature selection is the same repository acted upon.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb:24-30,59-62` computes:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```
`Shipit.github(organization:)` (`lib/shipit.rb:170-181`) looks up the org-specific config (and thus `webhook_secret`) purely from this attacker-suppliable string.

Downstream, `Handler#stacks`/`#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) resolves:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
```
and uses it via `Repository.from_github_repo_name(repository_name)` to find the `Stack` that will be acted on (e.g. `PushHandler#process` triggers `stack.sync_github`).

Because the signature check binds the HMAC secret to `repository.owner.login` while the write-side binds to `repository.full_name`, these are two independently attacker-controlled fields inside the very same JSON body whose only integrity guarantee is the raw-body HMAC. If a party legitimately possesses (or can compute/obtain) the `webhook_secret` of any one configured GitHub organization in this Shipit instance, they can craft a body where `repository.owner.login` equals that organization (so the correct secret is selected and the HMAC validates), while `repository.full_name` is set to `"OtherOrg/other-repo"` for a *different* organization's stack. The signature is computed over the full raw body, so this is not simple signature bypass — an attacker still needs a valid `webhook_secret` for at least one configured org — but there is no cross-check binding the two fields, so a webhook signed by Org A's secret can drive `PushHandler`/`StatusHandler`/etc. against a `Stack` belonging to Org B.

This matches the report's core bug class: a field that is acted upon (`repository.full_name`, used for stack resolution/mutation) is never checked against the field that was actually authenticated (`repository.owner.login`, used for secret selection) — an org-authenticated vs. repository-written mismatch.

### Impact Explanation
This allows unauthorized cross-repository/cross-organization writes: `PushHandler` calls `stack.sync_github`, which can append commits/trigger `GithubSyncJob` for a `Stack` not owned by the organization whose secret was actually used to authenticate the request. `StatusHandler` can create bogus commit statuses on unrelated stacks by supplying an arbitrary `sha`, independent of any repository binding at all (`StatusHandler` doesn't even use `repository_name`), which can pollute deploy-blocking CI status data used for shipping decisions. Because Shipit's deploy/ship logic can depend on commit statuses and sync state, this can influence which commits are considered "green"/deployable, i.e. contribute to an unauthorized deploy decision. This satisfies the "cross-repository writes / unauthorized deploy" impact bar.

### Likelihood Explanation
Requires the attacker to know a `webhook_secret` for at least one org configured in the same Shipit instance (typically the org they own/administer) — this is a real precondition but is not enumerated in the excluded "requires webhook_secret" clause in the same absolute sense as forging a signature outright, since here the attacker legitimately controls that secret for their own org and abuses the lack of cross-binding to reach into another org's stacks. In single-organization deployments (the common case, single `github:` block) `repository_owner` is not even used for org selection in the same way, so this is most relevant to explicit multi-org configs (`test/dummy/config/secrets_double_github_app.yml`, `docs/setup.md` multi-org examples), which the engine explicitly supports.

### Recommendation
After signature verification, validate that `repository.full_name`'s owner matches the `repository_owner` used to select the signing secret (or resolve the target repository/stack using the same authenticated organization context, not an independently-parsed field from the same untrusted payload). Reject events where these two do not match.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with distinct `webhook_secret`s (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As an attacker with knowledge of `OrgA`'s `webhook_secret` (e.g., an org owner who configured the GitHub App for OrgA), craft a JSON body:
```json
{ "ref": "refs/heads/main", "after": "<attacker-controlled-sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" } }
```
3. Compute `X-Hub-Signature` using `OrgA`'s `webhook_secret` over the raw body.
4. POST to `/github/webhooks` with `X-Github-Event: push`. `verify_signature` resolves `Shipit.github(organization: "OrgA")` and the signature validates.
5. `PushHandler#process` resolves `Repository.from_github_repo_name("OrgB/target-repo")` and calls `stack.sync_github`, mutating a stack that belongs to `OrgB`, whose secret was never used or checked. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
