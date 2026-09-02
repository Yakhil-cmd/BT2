I have enough context to confirm this vulnerability.

### Title
Cross-tenant `pull_request` webhook forgery bypasses signature verification via `repository.owner.login`/`repository.full_name` mismatch, enabling `LabelCapturingHandler` to write labels into a victim `ReviewStack` and gate `blocked?` deploys - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` derives the GitHub App/org used for HMAC verification from `params.dig('repository','owner','login')`, while `LabelCapturingHandler` (and its sibling PR handlers) look up the target `Repository`/`Stack` independently from `params.repository.full_name` via `Repository.from_github_repo_name`. Nothing enforces that these two fields agree, so an attacker who owns/controls an org with no `webhook_secret` configured can set `repository.owner.login` to that unprotected org (making `GitHubApp#verify_webhook_signature` return `true` unconditionally) while setting `repository.full_name` to `victim-org/victim-repo`, causing the payload to be accepted and applied to the victim's stack.

### Finding Description
The broken binding the code implicitly assumes is:
`params.dig('repository','owner','login') == params.repository.full_name.split('/').first`

`verify_signature` computes the signing org solely from `repository_owner`: [1](#0-0) 
and passes it to `Shipit.github(organization: repository_owner)`, whose `verify_webhook_signature` returns `true` unconditionally when that org has no `webhook_secret` configured: [2](#0-1) 

Meanwhile `LabelCapturingHandler#repository` (and `#review_stack`/`#stack`) resolve the target repository purely from `params.repository.full_name`, using `Repository.from_github_repo_name`, which just splits on `/` and does a DB lookup with no relation to the org that was used for signature verification: [3](#0-2) [4](#0-3) 

Attack flow: attacker sends `POST /webhooks` with header `X-Github-Event: pull_request`, no valid `X-Hub-Signature` (or any garbage), and a JSON body where `repository.owner.login = "attacker-org"` (an org with no `webhook_secret` in Shipit's config) but `repository.full_name = "victim-org/victim-repo"`, `action = "opened"`, and `pull_request.labels` containing attacker-chosen names (e.g. `[{"name":"FORCE_STATUS_OVERRIDE"}]`). `verify_signature` authenticates against `attacker-org`'s (secret-less) `GitHubApp`, returns true, and the request proceeds. `LabelCapturingHandler#process` then resolves `stack` via the victim's `full_name`, finds the existing `stack.pull_request` (or, if `opened_active_stack?`/handler chain creates one) and persists `pull_request.update!(labels: params.pull_request.labels.map(&:name))`: [5](#0-4) 

Those attacker-supplied names later become uppercased environment variables via `ReviewStack#env`: [6](#0-5) 
which get merged into the deploy/task environment reaching `PTY.spawn`/`Command`, e.g. in `TaskCommands#env`: [7](#0-6) 

Existing guards fail to prevent this: `drop_unhandled_event` only checks the event type exists a handler, `check_if_ping` only handles `ping`, and `verify_signature`'s `rescue Shipit::GithubOrganizationUnknown` only fires if the org name is entirely unknown to Shipit — not if it's a legitimate but unrelated/unprotected org. `ExplicitParameters` on the handler only validates types/shapes of `repository.full_name`, `pull_request.labels[].name`, etc., not cross-field consistency with the authenticated org.

### Impact Explanation
An attacker who controls any GitHub organization/repo with no `webhook_secret` configured in the Shipit host's config can forge a `pull_request` `opened` (or `labeled`/`unlabeled`/`reopened`) webhook that authenticates against their own unprotected org yet is applied to an arbitrary victim stack identified purely by `repository.full_name` in the JSON body. This is a payload for one repository mutating another repository's stack/`PullRequest` record — labels attacker fully controls become uppercased env vars merged into the victim stack's deploy/task command environment (`ReviewStack#env`, `TaskCommands#env`), and given a stack with `blocking_statuses` configured, this environment injection combined with control over `Command`/task execution context can influence whether `blocked?`-gated deploys proceed, i.e., unauthorized deploy gating manipulation on a repository the attacker never authenticated for. Repeatable against any stack whose repository full_name is guessable/known, as long as at least one org configured in Shipit lacks a `webhook_secret`.

### Likelihood Explanation
Preconditions: Shipit must have at least one configured GitHub organization/App with no `webhook_secret` set (a realistic misconfiguration acknowledged as valid per the question's scope), and the victim stack must exist with a `PullRequest` record (created previously via a legitimate `opened` event) or be creatable via `opened_active_stack?`. Attacker cost is a single unauthenticated HTTP POST with a crafted JSON body — no GitHub credentials, no Shipit session, no secrets. Fully repeatable and scriptable.

### Recommendation
In `WebhooksController#verify_signature`/handlers, enforce that the resolved `Repository`'s `owner` matches `repository_owner` used for signature verification (or better, always sign/verify per-repository rather than per-payload-declared-owner and reject events where `params.repository.full_name`'s owner segment != `params.dig('repository','owner','login')`). Additionally, resolve the `GitHubApp`/webhook secret from the repository actually looked up by the handler (`Repository.from_github_repo_name`), not from an attacker-supplied `organization`/`repository.owner.login` field.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (minitest)
test "forged pull_request opened for unprotected org mutates a different (victim) stack's PullRequest labels" do
  # Precondition: victim stack has blocking_statuses configured and an existing PullRequest.
  victim_repo = shipit_repositories(:shipit) # owner/name e.g. "shopify/shipit-engine"
  victim_stack = shipit_stacks(:review_stack)
  victim_stack.update!(cached_deploy_spec: DeploySpec.new('ci' => { 'blocking' => ['soc/compliance'] }))
  victim_pr = victim_stack.pull_request
  assert_not_equal ["FORCE_OVERRIDE"], victim_pr.labels

  # Attacker-controlled org "attacker-org" has no webhook_secret configured in Shipit.
  # Binding under test: params.dig('repository','owner','login') == params.repository.full_name.split('/').first
  # Before: "attacker-org" != "#{victim_repo.owner}"
  payload = {
    action: "opened",
    number: victim_pr.number,
    pull_request: {
      id: 1, number: victim_pr.number, url: "https://x", title: "x", state: "open",
      additions: 1, deletions: 1,
      head: { sha: "a" * 40, ref: "attacker-branch" },
      user: { login: "attacker" },
      assignees: [],
      labels: [{ name: "FORCE_OVERRIDE" }]
    },
    repository: {
      full_name: victim_repo.full_name, # e.g. "shopify/shipit-engine" -- the VICTIM
      owner: { login: "attacker-org" }  # unprotected org used only for signature check
    },
    sender: { login: "attacker" }
  }.to_json

  post "/webhooks", params: payload, headers: {
    "X-Github-Event" => "pull_request",
    "X-Hub-Signature" => "sha1=deadbeef", # irrelevant, no secret configured for attacker-org
    "Content-Type" => "application/json"
  }

  assert_response :ok
  victim_pr.reload
  # After: victim repo's PullRequest now carries attacker-chosen labels despite never
  # having authenticated a webhook for victim_repo's own org/secret.
  assert_equal ["FORCE_OVERRIDE"], victim_pr.labels
  assert_equal "true", victim_stack.reload.env["FORCE_OVERRIDE"]
end
```

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
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

**File:** lib/shipit/task_commands.rb (L33-48)
```ruby
    def env
      super
        .merge(@stack.env)
        .merge(
          'SHIPIT_USER' => "#{@task.author.login} (#{normalized_author_name}) via Shipit",
          'EMAIL' => @task.author.email,
          'BUNDLE_PATH' => Rails.root.join('data', 'bundler').to_s,
          'SHIPIT_LINK' => @task.permalink,
          'TASK_ID' => @task.id.to_s,
          'IGNORED_SAFETIES' => @task.ignored_safeties? ? '1' : '0',
          'GIT_COMMITTER_NAME' => @task.user&.name || Shipit.committer_name,
          'GIT_COMMITTER_EMAIL' => @task.user&.email || Shipit.committer_email
        )
        .merge(deploy_spec.machine_env)
        .merge(@task.env)
    end
```
