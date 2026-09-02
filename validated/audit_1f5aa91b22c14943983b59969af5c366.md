### Title
Webhook signature verification is a complete no-op when `webhook_secret` is unset, letting an unauthenticated attacker forge GitHub events that Shipit trusts as authentic - ([File: lib/shipit/github_app.rb])

### Summary
The external report's bug class is "a verification step exists, but a designed escape hatch lets the protected party bypass it, breaking the binding between what was verified and what is acted on." The same class exists in Shipit's GitHub webhook pipeline: `GitHubApp#verify_webhook_signature` treats a blank `webhook_secret` as automatic success, so `WebhooksController` accepts and processes *any* payload, with any claimed `repository`/`organization`, with no cryptographic binding at all between "the entity GitHub believes it is signing for" and "the stack/repository Shipit writes to."

### Finding Description
`WebhooksController#verify_signature` resolves which GitHub App/secret to check against from attacker-controlled payload fields, then delegates verification to `GitHubApp#verify_webhook_signature`: [1](#0-0) 

The verification method itself is: [2](#0-1) 

`return true unless webhook_secret` means that whenever an organization's GitHub App config in `secrets.yml`/credentials has no `webhook_secret` set — a state explicitly documented as optional and the default in `test/dummy/config/secrets.yml` (`webhook_secret: # nil`) — signature verification is skipped entirely: [3](#0-2) [4](#0-3) 

Once `verify_signature` passes (trivially, with no secret), `WebhooksController#create` dispatches the raw, attacker-supplied JSON directly to registered handlers: [5](#0-4) 

Those handlers resolve which `Stack`/`Repository`/`Commit` to mutate purely from unauthenticated payload fields (`repository.full_name`, `sha`, `pull_request.*`), with no additional origin check: [6](#0-5) [7](#0-6) [8](#0-7) 

The broken equality is: **"the GitHub organization the `X-Hub-Signature` supposedly proves the request came from" ≠ "the repository/stack/commit the handler actually mutates,"** because when no secret is configured the left-hand side is never actually checked — exactly analogous to the Nonces report where "the signer who produced the signature" was never actually re-verifiable/cancellable, letting stale/unauthorized authorizations be acted upon indefinitely.

### Impact Explanation
With no secret configured (a documented, supported configuration), any unauthenticated internet user can POST arbitrary JSON to `/webhooks` and have Shipit treat it as a genuine GitHub event for any repository it hosts. This lets an attacker:
- Forge `status` events to mark any commit's CI as `success` via `StatusHandler#process` (`commit.create_status_from_github!`), fabricating green CI signals used to gate deploys and to satisfy `merge.require`/`ci.require` checks.
- Forge `pull_request` `labeled`/`opened` events processed by `LabelCapturingHandler`/`OpenedHandler` to inject or advance pull requests in the automatic merge queue.
- Combined, this chain can move a malicious `MergeRequest` through `merge_status`/`ci` gating to the point where `MergeRequest#merge!` calls `stack.github_api.merge_pull_request`, causing Shipit's real GitHub App installation token to merge an attacker-chosen PR into the tracked branch — an **unauthorized merge**, one of the explicitly listed Critical impacts (unauthorized deploy/rollback/merge), performed with zero credentials.
- Forge `membership` events to create arbitrary `Team`/`User` records server-side (`MembershipHandler`), corrupting authorization bookkeeping used elsewhere (`Shipit.github_teams` membership checks in `User#authorized?`).

### Likelihood Explanation
Likelihood is conditional on a real-world deployment leaving `webhook_secret` blank, which the project's own setup documentation calls "optional" and which the bundled dummy/test configuration ships with unset by default. No credentials, no repository write access, and no prior session are required to exploit this — only knowledge of the `/webhooks` URL and the target's `owner/repo` full name.

### Recommendation
- Require `webhook_secret` to be present for any environment other than local development; fail closed (reject all events) rather than fail open (`return true`) when it's missing.
- Never derive the verification key from attacker-supplied payload fields (`repository.owner.login`/`organization.login`); resolve the expected organization/secret independently (e.g., from the installation ID or a per-repository server-side mapping) before trusting any payload content.
- Add tests asserting that an unset `webhook_secret` causes all webhook deliveries to be rejected, not implicitly trusted.

### Proof of Concept
1. Deploy Shipit with a GitHub App configuration that omits `webhook_secret` (matches `test/dummy/config/secrets.yml` and the "optional" guidance in `docs/setup.md`).
2. From any unauthenticated client, POST to `/webhooks` with headers `X-Github-Event: status` and no valid `X-Hub-Signature` (or any arbitrary value):
```
POST /webhooks
X-Github-Event: status
Content-Type: application/json

{"sha":"<malicious-commit-sha>","state":"success","context":"ci/required","repository":{"owner":{"login":"victim-org"},"full_name":"victim-org/victim-repo"}}
```
Because `webhook_secret` is blank, `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`), and `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) writes a forged "success" status onto the targeted commit, satisfying required-status checks Shipit uses to gate deploys/merges — with no authentication whatsoever.

*Note: I was unable to fully trace the background scheduler (`MergeRequest.schedule_merges`) invocation cadence and whether additional non-forgeable GitHub state (e.g., `mergeable` flag fetched live via `stack.github_api.pull_request`) would block the full forged-merge chain in practice; the webhook signature bypass itself and its direct write-primitives (fake CI status, fake PR/label state) are confirmed directly from the cited code.*

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** test/dummy/config/secrets.yml (L6-13)
```yaml
  github_api:
    token: t0k3n
  github:
    domain: # defaults to github.com
    app_id: 42
    installation_id: 43
    bot_login: "shipit[bot]"
    webhook_secret: # nil
```

**File:** docs/setup.md (L30-30)
```markdown
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-113)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
```
