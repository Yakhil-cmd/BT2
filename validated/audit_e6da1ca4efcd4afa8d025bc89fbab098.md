### Title
Cross-tenant commit-status forgery via unscoped SHA lookup in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` only validates a webhook's signature against the GitHub App configured for the organization named in the payload's own `repository.owner.login`, never against the repository/stack that will actually be mutated. `StatusHandler#process` then resolves the target commit(s) with a global, unscoped `Commit.where(sha: params.sha)` query and writes a `Status` row using each matched commit's own `stack_id`, so a signed "status" webhook from an attacker's own repository can write a `Status` into any other stack whose `Commit` table happens to contain a matching SHA.

### Finding Description
The broken binding is: `repository_owner` verified in `WebhooksController#verify_signature` (`Shipit.github(organization: repository_owner)`, using `params.dig('repository','owner','login')`) must equal the organization/stack that `Status#stack_id` is ultimately written against. It does not.

Code path:
- `app/controllers/shipit/webhooks_controller.rb:24-49` (`verify_signature`) authenticates the payload only against the org named in the payload itself: `Shipit.github(organization: repository_owner)` followed by `github_app.verify_webhook_signature(...)`. It never inspects which `Stack`/`Commit` the event's SHA might match.
- `app/models/shipit/webhooks/handlers/status_handler.rb:20-24` (`process`) then does `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — an **unscoped, engine-wide** lookup by SHA across all stacks/organizations, not filtered by `params['repository']['full_name']`.
- `app/models/shipit/commit.rb:165-169` (`create_status_from_github!`) calls `statuses.replicate_from_github!(stack_id, github_status)`, using **`commit.stack_id`** — i.e., whichever stack the matched `Commit` row happens to belong to.
- `app/models/shipit/status.rb:24-33` (`Status.replicate_from_github!`) persists the `Status` with that `stack_id`.

Because git SHAs are content-addressed, an attacker who forks a victim's public repository (or otherwise obtains a commit with an identical SHA, e.g. shared ancestor history) will have that exact SHA present in their own fork. A legitimate "status" event fired by GitHub for the attacker's own repository/org is signed with the attacker's own `webhook_secret` and organization, so `verify_signature` passes cleanly using the attacker-controlled `repository_owner`. `StatusHandler#process`'s SHA-only lookup then matches the victim's pre-existing `Commit` row (created for the victim's Stack from the victim's own sync), and writes a new `Status` (e.g. `state: success`) with `stack_id` equal to the **victim's** stack — a payload the victim's organization never sent and that never named the victim's repository anywhere in it.

None of the listed guards prevent this: `verify_signature` checks a different binding than the one being exploited (org signature validity, not org/stack correspondence to the mutated record); `drop_unhandled_event` only checks event type; the `ExplicitParameters` schema (`params do ... end` in `StatusHandler`) only validates payload shape, not repository scoping; there is no `force_github_authentication`, `User#authorized?`, or `stacks` scope involved at all in this webhook path, since webhooks are unauthenticated-by-session and rely solely on signature verification, which as shown is insufficient here.

### Impact Explanation
A crafted/naturally-occurring webhook from an attacker's own (legitimately configured) GitHub organization causes a `Status` row (state, description, target_url, context) to be written against a completely different, victim-owned `Stack`, without the victim's repository ever appearing in the payload. This directly matches the Critical category "a payload for one repository mutating another's stack, commit, task or task or team." Since `Commit#status` aggregates `statuses_and_check_runs` (`app/models/shipit/commit.rb:304-306`, `144-146`) and `deployable?`/`schedule_continuous_delivery` gate merges/deploys on status state (`app/models/shipit/commit.rb:227-229, 281-287`), an attacker can inject a forged `success` status for a commit that is actually `pending`/`failure` in the victim's real CI, potentially unblocking an otherwise-blocked deploy/merge on the victim's stack. This is repeatable against any victim Stack whose tracked repository shares any commit SHA with a repository the attacker can control (trivial via forking any public repo the victim tracks), and blast radius spans all tenants sharing the same Shipit installation/database.

### Likelihood Explanation
Preconditions are realistic and low-cost: the target repository must be public (common for open-source projects using Shipit) and hosted on a Shipit installation serving multiple GitHub orgs (documented and supported configuration, see `docs/setup.md` "Using Multiple GitHub Applications", `test/dummy/config/secrets_double_github_app.yml`). The attacker needs only to fork the public repo (preserving identical SHAs for shared history) and let any ordinary CI/status integration on their own fork post a status for that SHA — no Shipit credentials, no privileged GitHub App, and no victim repository interaction are required. This is fully repeatable and requires no timing race or privileged access.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and equivalent handlers) by the repository named in the payload, not just by SHA. Resolve the target stack(s) via `params['repository']['full_name']` and only consider commits belonging to that stack's repository (e.g., join `Commit` to `Stack`/`Repository` and filter by `repository.full_name == payload full_name`) before calling `create_status_from_github!`. Additionally, `verify_signature` should confirm that the signing organization matches the organization of every stack that will be mutated, not merely that some GitHub App exists for the payload's claimed owner.

### Proof of Concept
Minitest (`test/controllers/webhooks_controller_test.rb`-style, `ActionController::TestCase` or `ActionDispatch::IntegrationTest`):

```ruby
test "status webhook signed for attacker org must not write a Status onto a victim stack with same-SHA commit" do
  victim_stack = shipit_stacks(:shipit)          # org "shopify"
  victim_commit = shipit_commits(:first)         # belongs_to victim_stack, sha = "abc123..."

  # Simulate: attacker forked victim's repo, so their own repo contains an
  # identical commit with the same content-addressed SHA.
  attacker_owner = "attacker-org"

  # Signature is verified ONLY against attacker_owner's app/webhook_secret.
  Shipit.expects(:github).with(organization: attacker_owner).returns(
    stub(verify_webhook_signature: true)
  )

  body = {
    "sha" => victim_commit.sha,
    "state" => "success",
    "context" => "ci/attacker",
    "repository" => { "full_name" => "attacker-org/forked-repo", "owner" => { "login" => attacker_owner } }
  }.to_json

  request.headers['X-Github-Event'] = 'status'
  request.headers['X-Hub-Signature'] = 'sha1=whatever-valid-for-attacker-org'

  assert_no_difference -> { victim_stack.commits.reload; victim_commit.statuses.count }, "Status must not be written to victim stack from attacker-signed payload" do
    post :create, body:, as: :json
  end

  # Currently (vulnerable) this assertion FAILS:
  # victim_commit.reload.statuses.last.stack_id == victim_stack.id
  # even though payload never named victim_stack's repository.
end
```

Both sides of the equality to assert: `repository_owner` used in `verify_signature` (`attacker-org`) vs. the organization owning `victim_commit.stack` (`shopify`) — these differ, yet current code still permits the write, proving the vulnerability. If the fix scopes the `Commit` lookup by `params['repository']['full_name']`, the `assert_no_difference` block above will pass because no matching `(sha, repository)` pair exists for the victim's stack. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
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

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
