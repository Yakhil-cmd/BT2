This is critical: the `StatusHandler` matches commits **globally by SHA** with no repository scoping at all — `Commit.where(sha: params.sha)` [1](#0-0)  — while the signature that authorized the request was verified against the webhook secret of whatever organization is named in `params.dig('repository','owner','login')` [2](#0-1) . Nothing ties the `repository` object used for signature-org selection to the object actually acted upon.

### Title
Webhook signature is verified against a different organization/repository than the one the handler mutates - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and therefore which `webhook_secret`) to use for HMAC verification based solely on `params.dig('repository','owner','login')` (or `organization.login`) taken from the unauthenticated JSON body itself [3](#0-2) . The handlers that subsequently act on the payload use different fields to decide what to mutate: `Handler#repository_name` reads `payload.dig('repository','full_name')` [4](#0-3) , and `StatusHandler#process` doesn't even use the repository — it matches by commit SHA across the entire `commits` table [1](#0-0) . Nothing in the code enforces that `repository.owner.login` (used to pick the verifying secret) equals the owner segment of `repository.full_name` (used by the handler) or that the matched commit actually belongs to a stack under that organization.

### Finding Description
The binding that should hold is: `organization whose webhook_secret authenticated the request == organization whose repository/commit is mutated by the handler`. In practice:
- `verify_signature` picks `Shipit.github(organization: repository_owner)` purely from `params.dig('repository','owner','login')` in the raw JSON body [5](#0-4) .
- Shipit supports one `webhook_secret` per configured GitHub organization (multi-org config format documented in `config/secrets.development.example.yml`) [6](#0-5) .
- A holder of Organization A's webhook secret (e.g., anyone who can trigger real webhook deliveries for Org A, since Shipit is installed as a GitHub App on that org) can instead POST an arbitrary raw JSON body directly to `/webhooks`, setting `repository.owner.login = "orgA"` (so `Shipit.github(organization: "orgA")`'s secret verifies the HMAC) while filling every other field — `repository.full_name`, `sha`, `state`, `context`, etc. — with values belonging to a completely different repository/stack (Org B), because the signature check and the payload content are never cross-validated.
- For the `status` event this is maximally dangerous: `StatusHandler` looks up commits **only by `sha`**, with no repository/org filter at all [1](#0-0) , so an attacker who controls any org's webhook secret can inject a fabricated "success" `commit_status` for a commit SHA in a completely unrelated stack/repository.

### Impact Explanation
Commit statuses are consumed by `deployable?` checks that gate whether a commit can be deployed (via `required_statuses`/`blocking_statuses` from the deploy spec) [7](#0-6) . Being able to inject a forged "success" CI status for an arbitrary commit, using only a webhook secret scoped to a completely different organization, can make an otherwise-blocked/unreviewed commit appear deployable, leading to an **unauthorized deploy** of unvetted code — one of the explicitly accepted Critical/High impacts.

### Likelihood Explanation
This requires possession of *some* organization's `webhook_secret` configured on this Shipit instance — not privileged access to the target organization/repository, and not a Shipit session, `ApiClient` token, or GitHub App private key. Multi-tenant Shipit deployments (the documented multi-org `secrets.yml` layout) are exactly the scenario where one org's webhook secret is a materially weaker credential than access to another org's repositories, so the trust binding break is real and reachable through the engine's own code, not a hypothetical misconfiguration.

### Recommendation
In `WebhooksController#verify_signature`, after establishing which organization's secret verified the signature, re-derive and enforce that identity against every entity the handler subsequently touches: reject the payload unless `repository.full_name`'s owner segment matches `repository_owner`, and scope `StatusHandler` (and any other handler) lookups to commits/stacks belonging to that verified organization instead of matching bare SHAs or `full_name` strings from the unauthenticated body.

### Proof of Concept
1. Operate (or otherwise obtain the `webhook_secret` for) `orgA`, on a Shipit instance configured with the multi-org `github:` block shown in `config/secrets.development.example.yml`.
2. Build a `status` event payload: `{"sha": "<sha of a commit in orgB/private-repo tracked by this Shipit instance>", "state": "success", "context": "ci/required-check", "repository": {"owner": {"login": "orgA"}, "full_name": "orgA/some-repo"}}`.
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, body)>` and POST to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "orgA")` and succeeds, because `repository.owner.login == "orgA"` matches the secret used — even though the actual commit belongs to `orgB` [2](#0-1) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` and creates a forged "success" status on the `orgB` commit regardless of the repository field, since no repo scoping exists [1](#0-0) .

Note: I was not able to fully trace `Commit#create_status_from_github!` or the exact downstream deployability gating logic in this pass (index truncation), so the precise conditions under which a forged status alone flips `deployable?` to true (vs. requiring additional required-status names to match) should be verified by a Devin session with full file access before treating this as fully proven end-to-end.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

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

**File:** config/secrets.development.example.yml (L18-38)
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
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** app/models/shipit/deploy_spec.rb (L194-204)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```
