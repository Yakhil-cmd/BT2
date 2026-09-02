## Analysis

The `StatusHandler` (`app/models/shipit/webhooks/handlers/status_handler.rb`) is the key exploitable analog. It matches `Commit.where(sha: params.sha)` **globally, without scoping to a repository at all** — there is no `stacks`/`repository_name` filter like other handlers use. `Commit#create_status_from_github!` calls `add_status`, and `Status#state` directly controls `Commit#state` / CI green-ness used to gate deploys.

The verified binding vs. acted-upon binding breaks down as:

- **What the signature verification authenticates**: `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) selects the `github_app`/secret using `repository_owner` = `params.dig('repository','owner','login') || params.dig('organization','login')`.
- **What the handler actually acts on**: `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) looks up commits **only by `sha`**, with no relation to `repository.full_name` or `repository.owner.login` whatsoever — any commit row in the entire database sharing that SHA gets a status created, regardless of which stack/org/repo it belongs to.

Given `lib/shipit/github_app.rb:76-77` (`return true unless webhook_secret`), if the organization named in `repository.owner.login` has no `webhook_secret` configured (an explicitly documented "optional" setting — see `docs/setup.md:30` and `config/secrets.development.shopify.yml:9`), signature verification passes unconditionally for **any** body content. Because `Commit.where(sha:)` is unscoped, an attacker only needs to know a target commit SHA (public, visible on GitHub) and the fact that one configured org has no webhook secret — not that org's secret, not any repository write access, not a Shipit session, not an ApiClient token. This satisfies the "unprivileged attacker" and exclusion constraints in the rules (it does not require webhook_secret knowledge — the exploit is precisely the *absence* of one).

This is a legitimate analog to the C4 report's core bug class: a value used for the trust decision (`repository.owner.login`, gating which secret governs the request) is disjoint from the value the handler actually uses to select the object being mutated (`sha`, with zero repository binding), exactly mirroring "an organization that authenticated versus the repository that is written."

I could not fully verify from the index whether any Shipit deployment ships without a configured `webhook_secret` by default in production use, or whether every real-world engine mount enforces one — this depends on host-app configuration, which the rules say should not be assumed absent unless "documented" as optional (which it is, in `docs/setup.md`). I'm treating this as in-scope on that basis, but flagging the uncertainty.

### Title
Unscoped commit lookup in StatusHandler lets a webhook for one (secret-less) GitHub organization forge CI status on commits belonging to any other stack/repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target `Commit` rows solely by `sha`, without checking that the commit's repository matches the `repository.full_name`/`repository.owner.login` used by `WebhooksController#verify_signature` to select the signing organization. When an org's `webhook_secret` is unset (an explicitly supported, documented configuration), `GithubApp#verify_webhook_signature` returns `true` unconditionally, so an unauthenticated caller can submit an arbitrary `status` payload naming that org and any known commit SHA, and Shipit will apply the fabricated CI status to that commit even though it belongs to a completely different stack/repository/organization.

### Finding Description
`WebhooksController#verify_signature` binds trust to `repository_owner` (`params.dig('repository','owner','login') || params.dig('organization','login')`): [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` skips HMAC verification entirely when no secret is configured for that organization: [3](#0-2) 

This is a documented, supported configuration ("Webhook secret (optional)"): [4](#0-3) [5](#0-4) 

Meanwhile, unlike other handlers such as `PushHandler`/`CheckSuiteHandler` which scope their target by `repository_name` (`payload.dig('repository','full_name')`) via `Handler#stacks`: [6](#0-5) [7](#0-6) [8](#0-7) 

`StatusHandler#process` looks up `Commit` records purely by SHA, with no repository/stack scoping at all: [9](#0-8) 

`Commit#create_status_from_github!` then creates a `Status` row directly from the untrusted `state`/`context`/`description` fields: [10](#0-9) [11](#0-10) 

The organization identity that the signature check verifies (`repository.owner.login`) is never cross-checked against the repository that actually owns the mutated `Commit`. Any org configured without a `webhook_secret` becomes a skeleton key for forging commit statuses on **any** stack in the installation, because the acted-upon field (`sha`) is completely decoupled from the verified field (`repository_owner`).

### Impact Explanation
`Status` creation triggers `Commit#state` transitions, and CI status is what gates deploy eligibility across the engine (see `Status#enable_ci_on_stack` and `schedule_continuous_delivery`, and the `deployable_status` webhook transitions exercised in `test/models/commits_test.rb`). An attacker who can inject a fabricated `"success"` status for an arbitrary target repository's commit can make blocked/failing commits appear CI-green, enabling continuous-delivery jobs to deploy that commit — an unauthorized deploy resulting from a forged signal that was never actually verified for that repository. This satisfies the High-impact criterion of "escalation into…an unauthorized deploy."

### Likelihood Explanation
Likelihood is contingent entirely on host configuration: it requires at least one configured GitHub organization in the multi-tenant install to have no `webhook_secret` set — an explicitly supported and documented setup, not a misconfiguration outside the engine's own code. Given that, the attack requires no credentials of any kind: only knowledge of a target commit SHA (trivially obtainable from the public GitHub repository) and the target org's login (also public). No webhook secret, ApiClient token, or session is needed.

### Recommendation
`StatusHandler#process` (and any other handler that mutates records looked up only by a cross-repository-ambiguous key like `sha`) must scope its lookup through the same repository identity that `WebhooksController#verify_signature` cryptographically authenticated, e.g. by joining through `stacks`/`Repository.from_github_repo_name(repository_name)` as `PushHandler` and `CheckSuiteHandler` already do, rather than a bare `Commit.where(sha:)`. Additionally, consider requiring `webhook_secret` to be present for every configured organization, or rejecting cross-organization payload fields when it is absent.

### Proof of Concept
1. Configure Shipit with two orgs, e.g. `orgA` (no `webhook_secret` set) and `orgB` (has stacks with real commits).
2. Note a real commit SHA belonging to a stack under `orgB` (public on GitHub).
3. POST to `/webhooks` with header `X-Github-Event: status` and header `X-Hub-Signature` set to any arbitrary value, with body:
```json
{
  "sha": "<orgB commit sha>",
  "state": "success",
  "context": "ci/travis",
  "repository": { "owner": { "login": "orgA" } }
}
```
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"orgA"`, loads `orgA`'s `GithubApp`, and since `orgA.webhook_secret` is blank, `verify_webhook_signature` returns `true` unconditionally regardless of the bogus `X-Hub-Signature`.
5. `StatusHandler#process` runs `Commit.where(sha: "<orgB commit sha>")` and calls `create_status_from_github!`, creating a fabricated `"success"` status on the `orgB` commit — despite the request never being authenticated as coming from `orgB`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** config/secrets.development.shopify.yml (L9-9)
```yaml
    webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L23-34)
```ruby
    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end
```
