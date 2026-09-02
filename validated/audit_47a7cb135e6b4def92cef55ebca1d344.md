## Analysis

I traced the invariant the question claims is broken:

**Claimed binding:** `verify_signature` should ensure `params.dig('repository','owner','login')` (the org used to select the `GitHubApp` config and validate the HMAC) is the same tenant whose data (`params.repository.full_name` → `Stack`/`PullRequest`) gets mutated by the downstream handler.

**What the code actually does:**

`Shipit::WebhooksController#verify_signature` selects a `GitHubApp` purely from `repository_owner`, which is `params.dig('repository','owner','login')`, and calls `verify_webhook_signature`: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` returns `true` unconditionally whenever the configured `webhook_secret` for that org is blank: [3](#0-2) 

This "no-secret organization" configuration is real and exercised in the test fixtures (`OrgOne`/`OrgTwo` both have `webhook_secret:` blank): [4](#0-3) 

Once signature verification passes, `Shipit::WebhooksController#create` hands the **entire attacker-controlled JSON body** to the handler, and the handler never re-checks `repository.owner.login` — it independently re-resolves the target repository from `params.repository.full_name`: [5](#0-4) [6](#0-5) [7](#0-6) 

Nothing in the codebase enforces that `repository.owner.login` (used for signature selection) matches the owner segment embedded in `repository.full_name` (used for record resolution) — these are two independently attacker-supplied JSON fields in the same POST body.

**Exploit path:** An attacker crafts a `pull_request` webhook with `X-Github-Event: pull_request`, sets `repository.owner.login = "no-secret-org"` (a real org configured in Shipit but with a blank `webhook_secret`), and sets `repository.full_name = "victim-org/victim-repo"` (a real, unrelated victim tenant). `verify_signature` looks up `Shipit.github(organization: "no-secret-org")`, whose `verify_webhook_signature` returns `true` unconditionally regardless of the (even entirely fabricated) `X-Hub-Signature` header — so **no valid HMAC is required at all**. The request then reaches `LabelCapturingHandler#process`, which resolves `repository` and `stack` from `params.repository.full_name` = victim's repo, and for `action == "reopened"` on an active (non-archived) stack calls `capture_labels`, overwriting `stack.pull_request.labels` with attacker-chosen label names: [8](#0-7) 

These labels flow into `ReviewStack#env`, uppercased into environment variable keys: [9](#0-8) 

**On the "blocking_statuses" amplification claim:** I confirmed `blocking_statuses` gates `Commit#blocked?`/`Status#blocking?` and thus `deployable?`: [10](#0-9) [11](#0-10) 
However, `blocking_statuses` is driven by GitHub commit-status/check-run states configured in `shipit.yml`'s `ci.blocking`, not by pull-request labels — `LabelCapturingHandler` writes labels, not statuses. There is no code path shown connecting label names written by this handler to a "forced status" that flips `blocked?`. The question's phrase "a forced status can set/clear `blocked?`" refers to a *different*, status-event webhook path (not this handler), and combining it with `LabelCapturingHandler` in one PoC conflates two separate handlers/attacks without demonstrating an actual chained mechanism in the code I could inspect (e.g., no deploy-blocking logic reads `PullRequest#labels` or `ReviewStack#env` at deploy-gating time — `env` only affects the *executed environment* of `PTY.spawn`/`Command`, which is a genuine cross-tenant environment-variable injection into another tenant's deploy, but it is independent of `blocking_statuses`/`blocked?`).

### Title
Cross-tenant `pull_request` webhook forgery via no-secret org bypass lets an attacker overwrite another repository's PR labels and inject environment variables into its stacks — (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the signing organization solely from `repository.owner.login`, while `verify_webhook_signature` trivially returns `true` when that org's `webhook_secret` is blank, requiring no valid HMAC whatsoever. The downstream `LabelCapturingHandler` (and sibling PR handlers) independently resolve the target `Repository`/`Stack` from the unrelated `repository.full_name` field in the same forged body, so an attacker who only knows of one blank-secret org in the Shipit instance can write labels (and thus deploy-time env vars) onto any other configured repository's review stack.

### Finding Description
The broken equality: `params.dig('repository','owner','login')` (used to authenticate the request) **should always equal** the owner encoded in `params.dig('repository','full_name')` (used to locate the mutated record), but the engine never enforces this. `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) short-circuits to `true` when `webhook_secret` is blank — a supported, real configuration (see `test/dummy/config/secrets_double_github_app.yml`). `WebhooksController#verify_signature` (`webhooks_controller.rb:24-49`) only uses `repository_owner` (`repository.owner.login`) to pick the `GitHubApp`; it never checks that this owner matches `repository.full_name`. `LabelCapturingHandler#repository`/`#stack` (`label_capturing_handler.rb:110-118`) resolve the acted-upon repository purely via `Repository.from_github_repo_name(params.repository.full_name)`. An attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, body `{"action":"reopened","repository":{"owner":{"login":"no-secret-org"},"full_name":"victim-org/victim-repo"},"pull_request":{...,"labels":[{"name":"attacker-controlled"}]},...}`. Signature check passes unconditionally for `no-secret-org`; the handler then mutates `victim-org/victim-repo`'s `PullRequest#labels` via `capture_labels`. No later validation (`ExplicitParameters` schema only checks types/presence, not owner consistency) blocks this.

### Impact Explanation
The attacker writes arbitrary attacker-chosen strings into another tenant's `PullRequest#labels`, which `ReviewStack#env` (`review_stack.rb:84-93`) turns into uppercased environment variable keys merged into the environment passed to deploy/task commands (`TaskCommands#env`, `DeployCommands`). This is a cross-repository state-mutation primitive triggered by a payload that never authenticated against the victim repository's secret — matching "Critical: a payload for one repository mutating another's stack." It is repeatable against any repository configured in Shipit as long as at least one org anywhere in the Shipit instance has a blank `webhook_secret`. I could not confirm a concrete mechanism by which this specific handler's label writes flip `blocked?`/gate a deploy via `blocking_statuses`, since `blocking_statuses` is driven by commit statuses, not PR labels — that part of the chained claim is unsubstantiated by the code inspected.

### Likelihood Explanation
Requires only: (1) at least one Shipit-configured GitHub organization with `webhook_secret` unset (a documented/valid configuration state, not a hypothetical), and (2) knowledge of a victim `owner/repo` full name that has an active review stack. No GitHub credentials, no Shipit session, and no valid HMAC are needed — cost is a single crafted HTTP POST, fully repeatable.

### Recommendation
In `WebhooksController#verify_signature`, additionally require that `params.dig('repository','full_name')` (and/or `organization.login`) belongs to the same organization selected for signature verification, and reject the request otherwise. Do not allow `verify_webhook_signature` to silently return `true` for blank secrets in production; either require every configured org to set a `webhook_secret` or fail closed with a warning/alert when one is missing.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "pull_request reopened cannot write labels onto a repo whose owner didn't authenticate the webhook" do
  no_secret_org = "no-secret-org" # configured in secrets fixture with blank webhook_secret
  victim_stack = shipit_stacks(:review_stack) # e.g. owner "shopify"
  victim_full_name = victim_stack.repository.full_name
  before_labels = victim_stack.pull_request.labels

  body = {
    action: "reopened",
    number: victim_stack.pull_request.number,
    pull_request: { id: 1, number: victim_stack.pull_request.number, url: "u", title: "t",
                     state: "open", additions: 1, deletions: 1,
                     head: { sha: "a"*40, ref: "some-branch" },
                     user: { login: "attacker" }, assignees: [],
                     labels: [{ name: "attacker-label" }] },
    repository: { full_name: victim_full_name, owner: { login: no_secret_org } },
    sender: { login: "attacker" }
  }.to_json

  @request.headers['X-Github-Event'] = 'pull_request'
  @request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # invalid/irrelevant

  post :create, body: body, as: :json

  victim_stack.pull_request.reload
  # EXPECTED (no vulnerability): labels unchanged, request rejected (422) because
  #   repository.owner.login ("no-secret-org") != real owner of victim_full_name.
  # ACTUAL (vulnerable): response is 200 OK and
  assert_equal before_labels, victim_stack.pull_request.labels
end
```

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L70-102)
```ruby
          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
          end

          def opened?
            action == "opened"
          end

          def labeled?
            action == "labeled"
          end

          def unlabeled?
            action == "unlabeled"
          end

          def reopened?
            action == "reopened"
          end

          def action
            params.action
          end

          def pull_request
            params.pull_request
          end

          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-118)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
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
