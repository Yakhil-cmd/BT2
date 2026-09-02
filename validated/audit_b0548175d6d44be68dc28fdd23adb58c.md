### Title
`StatusHandler` writes GitHub statuses onto commits matched only by `sha`, ignoring the webhook's own repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Finding Description
The binding the question challenges is: `repository_params` (the `repository`/`organization` object merged into the webhook body) == the repository actually enforced against the matched `commit.stack`. Tracing the code shows these are **not** the same value anywhere in the write path.

`StatusHandler#process` does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [1](#0-0) 

This is a global, unscoped lookup by `sha` across *every* commit in the database, in every stack, in every repository. Nothing in `StatusHandler`, `Handler` base class, or `Commit#create_status_from_github!` cross-checks the payload's `repository.full_name`/`repository.owner.login` against `commit.stack.repository`. The `repository` object in the payload is consumed by the controller only for **signature routing**, not for authorization of the write:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

So `repository_owner` selects *which org's HMAC secret* to check the signature against, but once that signature check passes, the handler dispatch (`drop_unhandled_event`) only keys off `X-Github-Event`, and `StatusHandler.process` keys only off `sha`. The repository named in the payload is never checked against the repository that actually owns the matched commit.

The test at lines 42-59 confirms the write path (`Commit.where(sha:).create_status_from_github!`) succeeds for a matching sha with `repository_params` merged in but unchecked: [3](#0-2) . Swapping `repository_params` to point at an unrelated, attacker-owned repository in that exact test would still pass `commit.statuses.count` incrementing by 1, because in this test class `verify_signature` is unconditionally stubbed: `GithubHook.any_instance.stubs(:verify_signature).returns(true)` [4](#0-3) , and nothing downstream reads `repository_params` for authorization.

**Why this still matters outside the test stub, and why existing guards don't stop it in production:** `verify_signature` only proves the request was signed by *some* organization/app that Shipit trusts (`Shipit.github(organization: repository_owner)`), not that it was signed for the *specific repository* whose commit is being mutated. Because git commit SHAs are content-addressed, an attacker who controls **any** repository under an org/account that Shipit also trusts (a realistic scenario for a multi-tenant Shipit install serving many orgs/repos with a shared or per-org GitHub App) can push/cherry-pick a bit-for-bit-identical commit object (same tree, parents, author/committer metadata) into their own controlled repository. GitHub will emit a genuinely-signed `status` webhook for the attacker's own repository, but with a `sha` that collides with a commit that belongs to an entirely different stack. `verify_signature` passes (it's real, correctly signed for the attacker's own org), and `StatusHandler.process` then finds and mutates the unrelated stack's commit — because it never checks that `params['repository']` matches `commit.stack.repository`.

### Impact Explanation
An attacker who owns an unrelated repository trusted by the same Shipit deployment can inject fabricated CI status records (e.g., forge a "success" status from a name like `ci/tests`) onto a commit belonging to a completely different team's stack, without ever touching that stack's own webhook secret. This is repeatable against any commit whose SHA the attacker can reproduce content-identically. Depending on stack configuration (required statuses gating merge/deploy), this can result in an unauthorized deploy or merge decision being taken for a repository the attacker never authenticated against — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge."

### Likelihood Explanation
This requires: (1) a multi-tenant/shared Shipit deployment where the attacker legitimately owns or controls at least one repository whose organization/account is configured with a valid GitHub App/webhook secret in Shipit, and (2) the ability to reproduce an identical commit object (same tree/parents/metadata) as one that exists in the victim stack, which is feasible via forking/cherry-picking unmodified commits. It is not exploitable by a completely unaffiliated internet attacker with zero relationship to any trusted org — it requires the attacker to be a legitimate, signed webhook source for *some* org Shipit trusts, just not the *target* org/repo. This is a real but conditional cross-tenant confusion bug rooted purely in the missing repository check in `StatusHandler#process`.

### Recommendation
In `StatusHandler#process`, scope the `Commit` lookup by the payload's own repository, not just `sha`, e.g. resolve `params.dig('repository', 'full_name')` to a `Repository`, then restrict to `commit.stack.repository == that_repository` (or query commits through `Stack.where(repository: ...).commits.where(sha: ...)`) before calling `create_status_from_github!`. Apply the same repository-scoping check to other handlers that key writes purely by `sha` or PR number.

### Proof of Concept
```ruby
test ":state with mismatched repository_params still creates a Status for the specific commit (repository not enforced)" do
  request.headers['X-Github-Event'] = 'status'

  commit = shipit_commits(:first)
  attacker_repository_params = {
    'repository' => {
      'full_name' => 'attacker-org/attacker-owned-repo',
      'owner' => { 'login' => 'attacker-org' }
    }
  } # deliberately NOT shipit_commits(:first).stack.repository

  body = JSON.parse(payload(:status_master)).merge(attacker_repository_params).to_json

  assert_difference 'commit.statuses.count', 1 do
    post :create, body:, as: :json
  end
end
```
Binding to check before/after: `repository_params.dig('repository','full_name')` == `shipit_commits(:first).stack.repository.full_name`. Before code fix: mismatched, yet `commit.statuses.count` still increments by 1 — proving `repository_params` is inert for authorization in `StatusHandler#process` [1](#0-0) . After applying the recommended fix, this same test should fail to create a status (0 diff) because the repository check would reject the mismatch.

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

**File:** test/controllers/webhooks_controller_test.rb (L7-10)
```ruby
    setup do
      @stack = shipit_stacks(:shipit)
      GithubHook.any_instance.stubs(:verify_signature).returns(true)
    end
```

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
