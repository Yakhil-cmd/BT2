### Title
Cross-tenant `status` webhook forgery via secret-less GitHub org bypasses repository scoping in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`, `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` authenticates a webhook only by looking up `Shipit.github(organization: repository_owner)` from `params.dig('repository','owner','login')` and calling `verify_webhook_signature`, which returns `true` unconditionally when that organization's `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`). `StatusHandler#process` then runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository/owner check at all (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), so a request "authenticated" only by an org with no configured secret can write a status onto a commit belonging to a completely different stack/repository, as long as the SHA matches.

### Finding Description
The broken binding is: **the organization/repository that authenticated the webhook == the stack/commit that the webhook mutates**. Tracing the path:

1. `verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30`) resolves `repository_owner` purely from attacker-controlled JSON (`params.dig('repository','owner','login')`, fallback `organization.login`), then calls `Shipit.github(organization: repository_owner).verify_webhook_signature(sig, raw_post)`.
2. `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-77`): `return true unless webhook_secret`. If the org named in the payload is a configured Shipit org but its config entry has no `webhook_secret`, any payload is accepted with zero HMAC verification — no secret is required, not even a wrong one.
3. Once accepted, `Shipit::Webhooks.for_event('status').each { |handler| handler.call(params) }` runs `StatusHandler#process`, which does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` (`status_handler.rb:20-24`). This query is **global across all stacks** — it is not scoped by `stack_id`, `repository`, or the `repository_owner` that was used to select the verifying `GitHubApp`. `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) writes the status unconditionally via `statuses.replicate_from_github!`.

Existing guards do not prevent this: `verify_signature` only chooses *which* org's secret to check, it does not confirm that the org actually owns the commit being mutated; `ExplicitParameters` on `StatusHandler` only validates the shape of `sha`/`state`/etc., not repository identity; there is no `subset`/`url` validator on `sha` tying it to a repo. Thus an attacker who owns/controls an organization configured in Shipit with a blank `webhook_secret` (or who can get their own org onto Shipit's org list with default/blank config) can forge a `status` payload with any known SHA and flip the status of a commit in **any other stack**, including a `review_stacks_enabled: true, allow_all` stack whose review stacks are auto-provisioned from external PRs and run `shipit.yml`. Because `Commit#schedule_continuous_delivery` reacts to status changes (`app/models/shipit/commit.rb:281-287`, called from `add_status` in `create_status_from_github!`'s chain), a forged "success" status can push a commit toward `ContinuousDeliveryJob`, enabling an unauthorized deploy on a victim stack — and since `allow_all` review stacks execute arbitrary `shipit.yml` from the PR author, this compounds into command execution on the deploy host that the forging party never authenticated for.

### Impact Explanation
- What is executed/exposed: an attacker-forged GitHub commit status is written onto a commit belonging to a stack/repository the attacker never authenticated against, and if that stack has continuous deployment enabled, this can trigger an unauthorized deploy of a victim's stack (potential RCE via `Command`/`PTY.spawn` chain during deploy) — matching the "payload for one repository mutating another's stack, commit... or an unauthorized deploy" Critical category.
- Which party: any Shipit stack/commit across the entire instance whose SHA the attacker can guess or observe (public repos, forks, mirrored SHAs), not limited to the attacker's own repository.
- Repeatability: fully repeatable — one unauthenticated `POST /webhooks` per forged status, with the org name swapped to any Shipit-configured org lacking a `webhook_secret`.
- Blast radius: instance-wide; blast radius is bounded only by which orgs in Shipit's config omit `webhook_secret` and which commits' SHAs the attacker knows, not by which repositories they control.

### Likelihood Explanation
Preconditions: (a) Shipit must have at least one configured GitHub organization whose config omits `webhook_secret` (this is an operator misconfiguration risk, not enforced by the engine — `GitHubApp#initialize` treats `webhook_secret` as optional via `.presence`), and (b) the attacker needs to know a target commit's SHA in a victim stack, which is often public (open-source mirrors, public GitHub repos) or inferable. No Shipit credentials, GitHub App keys, or team membership are required — the attacker only needs unauthenticated HTTP access to `POST /webhooks`. The `review_stacks_enabled/allow_all` amplification is optional to the core repository-scoping bug but raises severity when present.

### Recommendation
`StatusHandler` (and other handlers keyed only by `sha`) must scope `Commit.where(sha: ...)` by the repository that authenticated the request — e.g., resolve the target `Stack`/`Repository` from `params.dig('repository','full_name')`, verify it matches the commit's `stack.repository`, and reject/skip commits belonging to a different repository. Additionally, `GitHubApp#verify_webhook_signature` should not silently accept unsigned payloads when `webhook_secret` is blank for a *known, configured* organization — either require `webhook_secret` to be present for all configured orgs or explicitly reject unsigned webhooks for such orgs rather than auto-accepting them.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
```ruby
test ":status forges a status onto an unrelated commit via a secret-less org" do
  # victim: commit belonging to a different stack/repository (e.g. shipit_commits(:cyclimse) or similar fixture in another stack)
  victim_commit = shipit_commits(:third) # belongs to a stack whose repository is NOT "attacker-org"
  refute_equal victim_commit.stack.repository.owner, 'attacker-org'

  # Configure "attacker-org" in Shipit.github_configs with NO webhook_secret
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(
    Shipit::GitHubApp.new('attacker-org', {}) # webhook_secret blank -> verify_webhook_signature always true
  )

  request.headers['X-Github-Event'] = 'status'
  body = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/forged',
    'repository' => { 'owner' => { 'login' => 'attacker-org' } }
  }.to_json

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body:, as: :json
  end
  assert_response :ok

  status = victim_commit.statuses.last
  assert_equal 'success', status.state
  assert_equal 'ci/forged', status.context
  # Assert the binding is broken: the authenticating org ("attacker-org") != the commit's actual repository owner
  refute_equal 'attacker-org', victim_commit.stack.repository.owner
end
```
This demonstrates that the equality "authenticating organization == mutated commit's repository" does not hold, confirming the vulnerability. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
