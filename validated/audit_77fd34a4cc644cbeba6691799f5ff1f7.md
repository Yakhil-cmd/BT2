### Title
`review/approved` `status` webhook writes across repositories via unscoped `Commit.where(sha:)`, flipping deployability on any stack sharing that SHA - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely `Commit.where(sha: params.sha)` with no filter on the repository that authenticated the webhook, so a genuinely-signed `status` event from an attacker-controlled repository can update the status/state of a `Commit` record belonging to an entirely different stack, as long as both records share the same SHA value. Combined with a `review/approved` required context and a `bot_login`-configured stack where auto-triggered continuous delivery runs under the app's bot identity, this can force or block a deploy the victim never approved.

### Finding Description
The broken binding the code should enforce is: `commit.stack.repository.full_name == webhook.payload['repository']['full_name']` for every `Commit` mutated by a `status` event. Instead, `StatusHandler#process` does: [1](#0-0) 
`Commit.where(sha: params.sha)` is a global, unscoped query across the entire `commits` table (not `stack.commits.where(sha:)`), and it iterates every match calling `commit.create_status_from_github!(params)` — which writes a new `Shipit::Status` row and re-evaluates `deployable?`/`blocked?`/`required?` for that commit's own stack: [2](#0-1) [3](#0-2) 

`Status#required?`/`blocking?` are evaluated purely from `context` string membership in the *victim stack's* `deploy_spec` configuration, not from which repository sent the webhook: [4](#0-3) 

The signature check in `WebhooksController#verify_signature` only proves the payload was signed by the GitHub App/organization named in the payload's own `repository.owner.login`/`organization.login` — it does not, and cannot, prove that the `sha` field inside that payload is unique to that repository: [5](#0-4) 

**Exploit flow:** The attacker owns a GitHub repository/organization with the Shipit GitHub App installed (a legitimate, unprivileged setup — anyone can create a repo and install a public app). The attacker crafts a commit whose SHA is identical to a commit that already exists in the victim's stack (Git SHAs are content-addressed over tree, parents, author/committer identity and timestamps and commit message; an attacker who can observe/replicate a public commit's exact metadata — e.g. because it originated from a shared open-source ancestor, a fork, or a cherry-pick with faithfully preserved metadata — can reproduce the same SHA in their own repo). The attacker then triggers (or directly emits) a `status` webhook on their own repository with `context: "review/approved"`, `state: "failure"`, for that shared SHA. GitHub signs this event with the attacker's own valid webhook secret, so `verify_signature` passes. `StatusHandler#process` then matches the victim's `Commit` row by bare SHA and calls `create_status_from_github!`, inserting a `failure` status under context `review/approved` on the victim's commit. If the victim stack requires `review/approved` as a required/blocking context, this failure status can flip `deployable?` to false (blocking an otherwise-good deploy) or, in the reverse case, a forged `success` could unblock/force a deploy that had not actually been approved. Because such stacks are commonly configured with `bot_login` (a service account, i.e. `Shipit.user`) driving `ContinuousDeliveryJob`, the resulting deploy/rollback executes automatically under that bot's credentials with no additional human review.

No existing guard intervenes: `verify_signature` only authenticates the sender's own organization, not the `sha` scope; `drop_unhandled_event` and `ExplicitParameters` (the `params do ... end` schema in `StatusHandler`) only validate the shape of `sha`/`state`/`context`, not the origin-repository binding; there is no `Stack`/`Repository` filter anywhere in `StatusHandler#process`.

### Impact Explanation
An attacker with no privileges on the victim's repository or Shipit instance can write arbitrary `Status` rows (any `context`, any `state`) onto commits belonging to a victim's stack, provided a shared SHA can be produced. This directly matches "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge" (Critical). The blast radius spans every stack configured with a `review/approved` (or any other) required/blocking context whose commit SHA can be replicated by the attacker, and repeatable per-SHA/per-status-context combination.

### Likelihood Explanation
The attacker needs: (1) their own GitHub repository/org with a webhook-signing-capable app installation — trivially available to any GitHub user; (2) a commit whose SHA collides with one in the victim's history — feasible when repos share ancestry (forks, vendored/shared open-source commits, cherry-picks that preserve author/committer/timestamp metadata), which is common practice and does not require a SHA-1 cryptographic collision, just content equality of a commit already known to the attacker. No secrets, sessions, tokens, or Shipit privileges are required. Preconditions on the victim side (a `review/approved`-gated stack with `bot_login`/continuous delivery configured) are a standard, documented Shipit configuration, not an edge case.

### Recommendation
Scope the commit lookup in `StatusHandler#process` (and any lookup-by-sha in webhook handlers generally) to commits whose `stack.repository` matches the repository identified in the webhook payload (`params.dig('repository','full_name')`/owner+name), e.g. `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { owner: ..., name: ... })`, mirroring the repository-scoping already used by `PushHandler`/`PullRequestHandler` style handlers.

### Proof of Concept
minitest plan (no live GitHub):
1. Create `repository_a` (victim) and `repository_b` (attacker), each with its own `Stack`.
2. Create `commit = victim_stack.commits.create!(sha: "deadbeef...", ...)`. Configure victim's `cached_deploy_spec`/deploy spec so `review/approved` is in `required_statuses`.
3. Assert baseline: `commit.reload.status.required?` context `review/approved` absent ⇒ `commit.deployable?` is `true` (or whatever the pre-attack baseline is).
4. Build a `status` event payload: `{ sha: commit.sha, state: 'failure', context: 'review/approved', repository: { full_name: repository_b.full_name, owner: {login: repository_b.owner} } }` — i.e., payload's `repository` is `repository_b`, but `sha` equals `commit.sha` which belongs to `repository_a`'s stack.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.new(...).call(payload)` directly (bypassing HTTP/signature layer, which is legitimate for `repository_b`'s own webhook secret in a real attack) or invoke `StatusHandler#process` directly with `ExplicitParameters`-wrapped params.
6. Assert the binding equality is violated: `commit.stack.repository.full_name` (`repository_a`) `!=` payload's `repository.full_name` (`repository_b`), yet `commit.reload.statuses.last.context == 'review/approved'` and `state == 'failure'` and `commit.deployable? == false` — proving repository_b's webhook mutated repository_a's commit/stack deployability.

### Citations

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

**File:** app/models/shipit/status/common.rb (L46-52)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end

      def required?
        commit.required_statuses.include?(context)
      end
```

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
