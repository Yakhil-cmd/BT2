### Title
Cross-tenant status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` bypasses repository binding and defeats `Commit#blocked?` gates - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit purely by `params.sha` with no check against the webhook's own `repository` field, unlike the base `Handler` class which provides a `stacks` helper scoped by `repository_name` for exactly this purpose. Because webhook signature verification (`WebhooksController#verify_signature`) validates the payload against the *organization named in the attacker-controlled `repository.owner.login` field*, an attacker who legitimately owns any repository registered on the same shared Shipit instance can sign a `status` webhook with their own valid `webhook_secret` while setting `sha` to a victim commit's sha and `context`/`state` to satisfy the victim stack's `ci.blocking` gate.

### Finding Description
The intended binding is: `entity permitted to satisfy blocking_status(stack S) == entity Shipit recognizes as belonging to S's repository/CI`. Tracing the code shows this is broken.

`Commit#blocked?` walks undeployed commits and asks each `Status#blocking?`, which is `!success? && commit.blocking_statuses.include?(context)` [1](#0-0) [2](#0-1) . A `Status` becomes satisfying purely by having `state: 'success'` and `context` equal to one of `stack.blocking_statuses` (from `shipit.yml`'s `ci.blocking`, e.g. `soc/compliance`) [3](#0-2) .

The only creation path for such a `Status` from a webhook is `StatusHandler#process`:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [4](#0-3) 
This performs a global lookup across *all* commits/stacks/repositories by the literal `sha` string in the JSON body — it never consults `payload.dig('repository', 'full_name')`. Contrast this with the base `Handler` class, which explicitly exposes a `stacks` helper scoped by `Repository.from_github_repo_name(repository_name)` for handlers to use [5](#0-4) ; `StatusHandler` simply does not use it. `commit.create_status_from_github!` then creates the `Status` using `commit.stack_id` (the correct owning stack) with attacker-supplied `state`/`context`/`created_at` [6](#0-5) [7](#0-6) .

Signature verification does not close this gap: `WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner)` where `repository_owner` is read straight from `params.dig('repository', 'owner', 'login')` in the attacker-controlled body [8](#0-7) . It only proves the request was HMAC-signed with *some org's* `webhook_secret` — the org the attacker names in their own forged `repository` object, which is decoupled from the `sha` field used to select the target commit. An attacker who legitimately owns/administers any repository onboarded to the same shared Shipit instance possesses that org's real webhook (or can trigger one), obtains a valid signature for that org, and then supplies an arbitrary `sha` belonging to a victim stack in a *different* org, plus `context: 'soc/compliance'`, `state: 'success'`.

The `ExplicitParameters` schema for `StatusHandler` only requires `sha`/`state` to be strings, with no cross-field validation tying `sha` to `repository` [9](#0-8) , and the `Status` model validates only `state` inclusion, not repository provenance [10](#0-9) . No other guard (`drop_unhandled_event`, model validations) checks repository ownership of the target commit.

### Impact Explanation
A single forged webhook creates a `Status` row attributed to the victim stack's commit that flips `blocking?` to false for that commit, and `Commit#blocked?`/`deployable?` for all downstream undeployed commits then evaluate as unblocked [11](#0-10) . `after_commit :schedule_continuous_delivery` on `Status` then re-triggers `Stack#trigger_continuous_delivery`, allowing the victim's continuous-deployment pipeline to proceed past the organization's configured compliance gate (e.g. SOC compliance) using a status that never originated from the victim's own CI or repository. This is a payload from one repository/org mutating another's commit/stack state and enabling an unauthorized deploy — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). The attack is repeatable against any commit sha in any stack on the shared instance, and since `sha` need only be a string matched by `Commit.where(sha:)`, the attacker requires no real git-object collision — only knowledge of the victim's commit sha (typically visible in public GitHub history/PRs or the Shipit UI itself).

### Likelihood Explanation
Preconditions: Shipit deployed as a multi-tenant/shared instance where more than one organization/repository is registered (each with its own `webhook_secret` under `Shipit.github(organization:)`), and the attacker legitimately controls at least one such repository (satisfying the stated "owns a repository" attacker capability) — a realistic Shipit deployment pattern given the per-organization GitHub App/webhook_secret configuration [12](#0-11) . Cost is a single signed HTTP POST to `/webhooks` with a `status` event, forged `repository.owner.login` naming the attacker's own org, and a target `sha`/`context` known from the victim's public commit history and `shipit.yml`. This is fully repeatable and requires no elevated privileges beyond owning any one onboarded repository.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to the repository asserted (and cryptographically bound) by the webhook, e.g. restrict to commits whose `stack` belongs to `Repository.from_github_repo_name(repository_name)` (using the existing `stacks` helper already defined in `Handler`), rejecting/ignoring statuses whose `sha` maps to a commit outside that repository's stacks.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "cross-tenant status forgery unblocks victim stack's blocking gate" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(cached_deploy_spec: DeploySpec.new('ci' => { 'blocking' => ['soc/compliance'] }))

  blocking_commit = victim_stack.commits.create!(
    sha: 'victimsha1', message: 'victim commit', author: shipit_users(:walrus),
    committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now
  )
  downstream_commit = victim_stack.commits.create!(
    sha: 'victimsha2', message: 'downstream', author: shipit_users(:walrus),
    committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now
  )

  assert_predicate downstream_commit, :blocked? # gate is active, no success status yet

  # Attacker: owns unrelated repo "attacker/repo", signs with THEIR org's webhook_secret,
  # but targets victim's commit sha with the victim's blocking context.
  forged_payload = ExplicitParameters::Parameters.new(
    sha: 'victimsha1', state: 'success', context: 'soc/compliance',
    description: nil, target_url: nil, created_at: Time.now.to_s, branches: []
  )

  Shipit::Webhooks::Handlers::StatusHandler.call(
    'sha' => 'victimsha1', 'state' => 'success', 'context' => 'soc/compliance',
    'repository' => { 'full_name' => 'attacker/repo', 'owner' => { 'login' => 'attacker' } }
  )

  refute_predicate downstream_commit.reload, :blocked? # gate bypassed by unrelated repo's webhook
end
```
Both sides of the binding diverge: the signature-verified entity is `attacker` (an unrelated org/repo), while the mutated record belongs to `victim_stack`'s repository — confirming the vulnerability.

### Citations

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end
```

**File:** app/models/shipit/deploy_spec.rb (L202-204)
```ruby
    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/status.rb (L16-16)
```ruby
    validates :state, inclusion: { in: STATES, allow_blank: true }, presence: true
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end
```
