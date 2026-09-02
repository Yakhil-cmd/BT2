### Title
Cross-organization webhook signature confusion — verified GitHub organization is not bound to the repository actually acted upon (`app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken directly from the unauthenticated request body. Once the signature check passes, every event handler (`PushHandler`, `CheckSuiteHandler`, `StatusHandler`, etc.) looks up the target `Stack`/`Repository` using a *different* field of the same untrusted JSON object — `repository.full_name`. Nothing enforces that `full_name` is consistent with `owner.login`. This is the exact "field acted on but never covered by the verified signature" pattern described in the analog report: the signature only binds the request to *an organization's secret*, not to the repository that is subsequently written to.

### Finding Description
- `verify_signature` picks the org to verify against: [1](#0-0) [2](#0-1) 

- After verification succeeds, handlers resolve the affected repository/stacks using an unrelated field of the same payload: [3](#0-2) 

- `PushHandler` uses this `stacks` scope, keyed only by `repository.full_name` and `ref`/`after` (both attacker-controlled), to trigger a GitHub sync for whichever stack matches: [4](#0-3) 

- `CheckSuiteHandler` similarly schedules check-run refreshes for any stack whose repository name matches `full_name`, independent of the org used for signing: [5](#0-4) 

**Binding that should hold:** `organization_verified_by_signature == owner(repository_acted_on)`.
**Binding that actually holds:** `organization_verified_by_signature == payload["repository"]["owner"]["login"]`, while `repository_acted_on == payload["repository"]["full_name"]`. These two payload fields are never cross-checked against each other.

### Impact Explanation
An attacker who knows the `webhook_secret` for *any* one GitHub organization configured on this Shipit instance (a realistic scenario given the documented multi-org support in `docs/setup.md`/`README.md`, where each customer org owns and can view its own App's webhook secret) can forge a valid `X-Hub-Signature` for that org, while setting `repository.full_name` in the payload to name a stack that belongs to a completely different, unrelated organization on the same Shipit instance. Because signature verification only checks that *some* secret matches the org named in `repository.owner.login`, and the handlers act on `repository.full_name` instead, the attacker can:
- Force `PushHandler` to invoke `stack.sync_github(expected_head_sha: <arbitrary sha>)` on a victim organization's stack, which can trigger deploy-candidate computation/auto-deploy behaviour for a stack the attacker has no legitimate relationship to.
- Force `CheckSuiteHandler`/`StatusHandler` to manipulate commit status/check-run state for a victim stack, corrupting the CI gating that governs deploy eligibility and the merge queue (`MergeRequest`/`ProcessMergeRequestsJob`).

This is an unauthorized write to another organization's stack state and can influence unauthorized deploys, satisfying the report's "unauthorized deploy" criterion, without requiring any Shipit session, API token, or the victim org's own secret.

### Likelihood Explanation
Requires only knowledge of one legitimate GitHub App webhook secret in a multi-org Shipit deployment (a config pattern the project explicitly documents/supports) and the ability to send an arbitrary HTTP POST to the public `/github/webhooks` endpoint — no Shipit session, API client token, or GitHub credentials for the victim org are needed. I was not able to fully trace whether `Stack#sync_github` on its own can trigger an *automatic* deploy without a continuous-deployment configuration being enabled on the victim stack (I could not locate/confirm that code path within available context), so the practical severity depends on whether the victim stack has autodeploy/continuous-deployment enabled; regardless, unauthenticated cross-organization mutation of stack/commit/check-run state is achievable.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`/`Handler#stacks`), require that `payload.dig('repository','full_name')` and `payload.dig('repository','owner','login')` are mutually consistent (i.e., `full_name` must start with `"#{owner_login}/"`), and reject the webhook otherwise. More robustly, resolve the target `Stack`/`Repository` strictly by `repository.owner.login` (the same field used for signature-org selection) rather than trusting `full_name` independently.

### Proof of Concept
1. Attacker legitimately administers a GitHub App for `org-attacker`, which is registered with this Shipit instance and has webhook secret `S_attacker` (known to the attacker).
2. Attacker crafts a `push` event payload:
```json
{
  "repository": {
    "owner": {"login": "org-attacker"},
    "full_name": "victim-org/victim-repo"
  },
  "ref": "refs/heads/main",
  "after": "deadbeef...arbitrary sha"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_attacker, raw_body)>` and POSTs to `/github/webhooks` with `X-Github-Event: push`.
4. `verify_signature` computes `repository_owner = "org-attacker"`, fetches `Shipit.github(organization: "org-attacker")`, and the signature validates successfully [1](#0-0) .
5. `PushHandler#process` runs `stacks` (resolved via `repository.full_name = "victim-org/victim-repo"`, unrelated to `org-attacker`) and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack [6](#0-5) , an organization the attacker never authenticated for.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L6-18)
```ruby
      class CheckSuiteHandler < Handler
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
        end
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
      end
```
