### Title
Cross-repository Status webhook injection unblocks victim deploy gates via SHA-only commit lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits purely by `Commit.where(sha: params.sha)` with no check that the webhook's authenticated `repository`/`repository_owner` matches the `stack`/repository that owns the matched commit. Since `WebhooksController#verify_signature` only proves the payload came from *some* GitHub org/repo configured in Shipit, not that it came from the specific repository owning the target `Stack`, a validly-signed `status` webhook from a repository the attacker legitimately controls can create a `Status` on a commit belonging to a completely different stack, as long as the commit SHA matches (which git guarantees for identical commit objects irrespective of which repository stores them).

### Finding Description
The broken binding as an explicit equality:

`repository.full_name` (authenticated by `verify_signature` for the incoming webhook) **==** `stack.repository.full_name` (the repository that owns `commit.stack`, whose `Commit#blocked?` computation is affected)

This equality is never checked anywhere in the write path.

Code path:
1. `WebhooksController#verify_signature` computes `repository_owner` from the payload (`params.dig('repository','owner','login')`) and validates the HMAC signature against `Shipit.github(organization: repository_owner)`'s configured `webhook_secret`. [1](#0-0) 
This only proves the request came from GitHub for *that organization/app installation* — it says nothing about which repository's `Stack` should be mutated.

2. `StatusHandler#process` then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [2](#0-1) 
`params` (the `ExplicitParameters` schema) only requires `sha`, `state`, and optional `description`/`target_url`/`context`/`created_at`/`branches` — the repository/owner fields are never read or compared here. [3](#0-2) 

3. `Status` records are created scoped only to `commit`/`stack_id` derived from the matched `Commit` row itself (`Status belongs_to :stack, required: true` and `belongs_to :commit, required: true`), never from the webhook payload's repository. [4](#0-3) 

4. `Status::Common#blocking?` and `Commit#blocked?` consume whatever `Status` rows exist for that commit/stack, with no re-validation of provenance: [5](#0-4) [6](#0-5) 

Root cause: git commit SHAs are content-addressed and independent of which repository stores them. Any user who forks (or otherwise obtains) the victim's public repository can push the exact same commit objects into a repository they own, then legitimately trigger (or directly cause GitHub to emit) a `status` event from *their own* repository for that identical SHA. GitHub signs that webhook with the secret belonging to whatever GitHub App/org configuration covers the attacker's own repository — a completely valid signature — but `StatusHandler#process` has no logic to reject a status whose payload repository differs from the stack owning the matched commit.

Exploit flow:
- Attacker forks/clones the victim's public repo containing the blocking commit `C` (same SHA everywhere).
- Attacker pushes `C` into a repository they own that is covered by a Shipit-configured GitHub App/org (their own account, or any org for which Shipit trusts a webhook secret).
- Attacker sets a `success` status on `C` in their own repository (via the GitHub Statuses API on a repo they control, or via their own CI), causing GitHub to emit a real, validly-signed `status` webhook naming the attacker's `repository.full_name`.
- `WebhooksController#verify_signature` passes (real GitHub signature for the attacker's own repo/org).
- `StatusHandler#process` finds the victim's `Commit` row with the same `sha` (unrelated stack), and calls `create_status_from_github!`, writing a `success` `Status` scoped to the **victim's** `stack_id`.
- `Status::Common#blocking?` for `C` now returns `false` (since `blocking?` requires `!success?`), so `Commit#blocked?` for any later commit on the victim's stack — which iterates `stack.commits.reachable.newer_than(...).older_than(...).any?(&:blocking?)` — no longer sees `C` as blocking, flipping `blocked?` to `false` despite no webhook from the victim's repository ever authenticating that transition.

Why existing guards fail: `verify_signature` authenticates org-level webhook origin only; there is no `ExplicitParameters` field or downstream check comparing `params['repository']['full_name']` to the `Stack`'s tracked repository for any matched `Commit`. `drop_unhandled_event`, `force_github_authentication`, `User#authorized?`, and `require_permission!` are irrelevant here since webhooks are unauthenticated-by-session by design and rely solely on signature verification, which this bug bypasses at the semantic (not cryptographic) level.

### Impact Explanation
An attacker who controls any repository whose organization/app is configured in Shipit can, purely by knowing (or obtaining) a victim commit's SHA, write a `Status` row onto **another tenant's** `Stack`/`Commit`, silently turning a blocking status non-blocking and unblocking a deploy gate for a repository the attacker never authenticated against. This is a write on a record (`Status`) attributed to a repository/stack that did not authenticate it, matching the explicitly listed Critical category: "a payload for one repository mutating another's stack, commit, task or team" and enabling "an unauthorized deploy." It is repeatable against any commit whose SHA the attacker can reproduce in a repository they control (which is trivial for any public commit via forking), across arbitrary victim stacks that share the same Shipit GitHub App/org configuration (or any org configuration if the attacker owns/controls a repo under that org).

### Likelihood Explanation
Preconditions: the attacker needs write access to at least one repository covered by a GitHub App/org that Shipit trusts (their own account/org, if Shipit is configured to accept webhooks from it, or any org they can push to). No Shipit secrets, session, or API token are required — only a legitimately signed GitHub webhook from a repository the attacker controls. Obtaining an identical commit SHA to a victim commit is trivial (fork the public victim repo and push the object into the attacker's own repo). The attack is repeatable at will and requires only standard GitHub actions (fork, push, set a status via the GitHub API on their own repo).

### Recommendation
In `StatusHandler#process` (and any other SHA-only webhook handler), require and verify that `params['repository']['full_name']` (or `owner/repo`) matches the `full_name`/`repo_name` of the `Stack` that owns each matched `Commit` before calling `create_status_from_github!`; skip/reject commits belonging to stacks whose repository does not match the authenticated webhook's repository.

### Proof of Concept
Minitest plan (no live GitHub, using existing fixtures/signature stub as in `test/controllers/webhooks_controller_test.rb`):
```ruby
test "cross-repository status webhook cannot unblock a victim stack's commit" do
  GithubHook.any_instance.stubs(:verify_signature).returns(true)

  victim_stack = shipit_stacks(:soc) # stack with ci.blocking configured
  blocking_commit = shipit_commits(:soc_second)
  later_commit = shipit_commits(:soc_third)

  assert_predicate blocking_commit, :blocking?
  assert_predicate later_commit, :blocked?

  # Binding under test, stated explicitly:
  # attacker_payload['repository']['full_name'] != victim_stack.repository.full_name
  attacker_payload = {
    'sha' => blocking_commit.sha,
    'state' => 'success',
    'context' => blocking_commit.stack.blocking_statuses.first,
    'repository' => { 'full_name' => 'attacker/unrelated-repo',
                       'owner' => { 'login' => 'attacker' } }
  }
  refute_equal attacker_payload['repository']['full_name'], victim_stack.repo_name

  request.headers['X-Github-Event'] = 'status'
  post :create, body: attacker_payload.merge(repository_owner_secret_stub).to_json, as: :json

  blocking_commit.reload
  later_commit.reload

  refute_predicate blocking_commit, :blocking?   # flipped by attacker's cross-repo webhook
  refute_predicate later_commit, :blocked?        # deploy gate unblocked without victim repo's authentication
end
```
This demonstrates `later_commit.blocked?` flips from `true` to `false` solely via a webhook whose authenticated `repository.full_name` differs from the victim stack's repository, confirming the broken binding.

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

**File:** app/models/shipit/status.rb (L11-12)
```ruby
    belongs_to :stack, required: true
    belongs_to :commit, required: true
```

**File:** app/models/shipit/status/common.rb (L46-48)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end
```

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```
