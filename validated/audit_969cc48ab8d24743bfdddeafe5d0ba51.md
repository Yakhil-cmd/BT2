### Title
Cross-organization forged commit status can mark any stack's commit as CI-successful, unlocking auto-merge/auto-deploy - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification from an **unverified** field of the payload itself (`repository.owner.login`, with fallback to `organization.login`), then verifies the raw body against that org's `webhook_secret`.<cite repo="Camomtat/shipit-engine--006" path="app/controllers/shipit/webhooks_controller.rb" start="24,59" end="30,62" /> Once the signature check passes, the dispatched handler for the `status` event, `StatusHandler`, resolves the target **purely by commit SHA, with no scoping to the organization that signed the request or to any repository at all**: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [1](#0-0) 

### Finding Description
In a multi-tenant Shipit install, several GitHub organizations/Apps can be configured, each with its own `webhook_secret`, looked up via `Shipit.github(organization:)`. [2](#0-1)  An attacker who administers one such low-privilege organization (e.g. their own org onboarded onto the shared Shipit instance) knows that org's `webhook_secret` and can compute a valid `X-Hub-Signature` for **any** raw JSON body of their choosing, because `verify_webhook_signature` just HMACs the raw payload against the secret for the org named in the payload. [3](#0-2) 

The broken binding is: *the organization whose secret authenticated the request* vs. *the commit/repository the handler actually writes to*. The `StatusHandler` never checks `payload.dig('repository','full_name')` against the commit's owning stack/repository — it only requires `sha` and `state`. [4](#0-3)  Commit SHAs from a victim organization's stacks are public information (visible on GitHub, in Shipit's own UI/API, in PR/commit URLs). So the attacker can:

1. Set `repository.owner.login` (or `organization.login`) to their own org, so `verify_signature` picks their own known `webhook_secret` and the HMAC check passes.
2. Set `sha` in the body to a real SHA belonging to a victim stack in an entirely different, unrelated organization on the same Shipit instance.
3. Set `state` to `success`.

Because `Commit.where(sha: params.sha)` is a global, unscoped lookup across the whole Shipit installation, this forged status is applied to the victim's commit via `Status.replicate_from_github!`, which creates a `Shipit::Status` record tied to the victim stack. [5](#0-4) 

### Impact Explanation
Creating a fake successful `Status` directly feeds `Commit#status`, `Commit#deployable?`, and `Commit#schedule_continuous_delivery`. [6](#0-5) [7](#0-6)  A commit's `deployable?` becomes true once it has a `success?` status (and is not blocked), and `add_status` explicitly calls `stack.schedule_merges` when the new status is `pending` or `success`, and fires `ContinuousDeliveryJob` when `stack.continuous_deployment?` is enabled. [8](#0-7)  This lets an unprivileged, unrelated organization owner remotely mark a victim commit as "CI green" and trigger an **unauthorized deploy or auto-merge** on a stack/repository they have no access or credentials to — a cross-organization write achieved purely by forging a webhook body, without ever holding a Shipit session, `ApiClient` token, or the victim's `webhook_secret`.

### Likelihood Explanation
Requires only that the attacker be a legitimate (even low-trust) tenant organization on a multi-org Shipit deployment with known `webhook_secret`, and knowledge of a target commit SHA (trivially obtainable from GitHub). No social engineering, GitHub App private key, or victim credentials are required. This is a realistic configuration for the documented multi-org support (`Shipit.github(organization:)` / `github_teams`, `oauth.teams`). [9](#0-8) 

### Recommendation
`StatusHandler` (and `Handler` in general) should scope lookups to the repository declared in the signed payload, and `WebhooksController#verify_signature` should cross-check that the organization used to select the webhook secret actually matches (is a prefix/owner of) the `repository.full_name` used later by handlers, rejecting any payload with a mismatch. Concretely:
- In `StatusHandler#process`, restrict to commits belonging to `stacks` (i.e., `Repository.from_github_repo_name(payload.dig('repository','full_name'))`) rather than a bare `Commit.where(sha: ...)` across the entire installation.
- Add an explicit invariant check in `verify_signature` that `repository.full_name.split('/').first.casecmp?(repository_owner)` (or equivalent), rejecting the webhook otherwise.

### Proof of Concept
1. Attacker's org `evil-org` is a legitimate Shipit tenant, with a known `webhook_secret` `S`.
2. Attacker finds a public commit SHA `abc123` in `victim-org/victim-repo`, tracked as a Shipit commit belonging to stack `victim-stack`.
3. Attacker builds body:
```json
{
  "sha": "abc123",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "evil-org" }, "full_name": "evil-org/whatever" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S, body)` and sends `POST /webhooks` with header `X-Github-Event: status`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "evil-org")` and verifies successfully against `S`. [10](#0-9) 
6. `StatusHandler#process` runs `Commit.where(sha: "abc123")`, finds the victim commit belonging to `victim-stack`, and calls `create_status_from_github!`, creating a `success` `Status` scoped to `victim-stack`. [1](#0-0) 
7. If `victim-stack.continuous_deployment?` is enabled or the merge queue is active, this triggers `stack.schedule_merges` / `ContinuousDeliveryJob`, causing an unauthorized deploy/merge on the victim stack. [7](#0-6)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L6-18)
```ruby
      class StatusHandler < Handler
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/commit.rb (L215-229)
```ruby
    def checks
      @checks ||= CommitChecks.new(self)
    end

    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

**File:** docs/setup.md (L125-142)
```markdown
**`github.oauth.teams`** optional, required only if you want to restrict access to a set of GitHub teams.

If it's missing, the Shipit installation will be public unless you setup another authentication method.

After you change the list of teams, you have to invoke `bin/rake teams:fetch` to prefetch the team members.

For example:

```yml
production:
  github:
    oauth:
      id: (your application's Client ID)
      secret: (your application's Client Secret)
      teams:
        - Shipit/team
        - Shipit/another_team
```
```

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
