### Title
Cross-Repository Status Forgery via Organization-Keyed Webhook Signature Bypassing Repository Scoping - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which `webhook_secret` to validate an incoming GitHub webhook against based on an **unverified** field taken from the JSON body itself (`repository.owner.login`), before that body has been authenticated. Once the HMAC check passes for that organization's secret, the entire raw JSON body — including the `repository` field that decided which secret to use — is handed unchanged to the event handlers. `StatusHandler`, however, never re-checks that the commit it updates actually belongs to the repository/organization whose secret validated the request: it resolves target commits globally by SHA (`Commit.where(sha: params.sha)`), with no scoping to the repository named in the payload. This breaks the intended binding "the organization whose secret authenticated this payload" == "the repository the payload is allowed to mutate."

### Finding Description
1. `verify_signature` computes `repository_owner` from the raw, not-yet-verified body and uses it to look up which app/secret to check the HMAC against: [1](#0-0) [2](#0-1) 

2. `GitHubApp#verify_webhook_signature` only checks that the raw body's HMAC matches the secret configured for whatever organization was named in `repository_owner` — it has no way to assert that the rest of the payload (e.g. a different `repository.full_name`, or a `sha` referencing a commit in a different repo) is consistent with that organization: [3](#0-2) 

3. Once verification passes, the full parsed payload is dispatched to handlers unmodified: [4](#0-3) 

4. `StatusHandler#process` resolves the commit purely by `sha`, with **no scoping to a repository, stack, or organization at all** — unlike `PushHandler`, which at least filters `stacks` by `branch`: [5](#0-4) [6](#0-5) 

Because a GitHub commit SHA is public information (visible on the target repo's GitHub page, PRs, etc.), an attacker who legitimately controls a GitHub App installation on **their own** organization (and therefore knows/controls that organization's `webhook_secret`, e.g. from `config/secrets.yml`'s multi-org section documented in `docs/setup.md`) can:
- Craft a `status` (or other) webhook JSON body whose `repository.owner.login` is their own org (so `verify_signature` looks up and validates against *their own* secret, which they know), while including a `sha` value copied from a commit in a **completely different, unrelated tracked repository**.
- The HMAC check passes because it is only checking the raw bytes against the correct (attacker-known) secret for the attacker's own org — it never asserts that `sha`/other fields "belong" to that org.
- `StatusHandler` then finds `Commit.where(sha: <victim-repo commit sha>)` — which resolves to the **victim stack's commit**, entirely outside the attacker's own organization — and calls `create_status_from_github!`, forging an arbitrary CI status (e.g. `success`) on it.

Before/after the attacker's request:
- Before: attacker only has legitimate control over webhook delivery for their own GitHub org/app installation; they have no relationship to the victim's tracked repository.
- After: a `Status` record is created against the victim's `Commit`, as if verified by the victim's own trusted webhook.

### Impact Explanation
`Status` creation is not inert — `Commit#add_status` (invoked via `create_status_from_github!`) schedules continuous delivery and merge-queue processing whenever a commit's simple status transitions to `success`/`pending`: [7](#0-6) 
and `MergeRequest#all_status_checks_passed?`/`ProcessMergeRequestsJob` consult these forged statuses to decide whether to auto-merge a pull request via the app's GitHub credentials: [8](#0-7) [9](#0-8) 

A forged "success" status on an unrelated stack's commit can therefore cause the Shipit instance to trigger continuous deployment or auto-merge a pull request into a repository the attacker has no relationship to, using the app's GitHub App token — this is an unauthorized deploy/merge, satisfying the Critical impact bar (cross-repository writes / unauthorized deploy or merge).

### Likelihood Explanation
Exploitation requires the attacker to control the webhook secret/configuration of at least one GitHub organization onto which the same Shipit instance's GitHub App is installed (a normal, unprivileged position for a customer/org admin in any multi-org Shipit deployment, as documented in `docs/setup.md`'s "Using Multiple GitHub Applications" section), plus knowledge of a target commit SHA in another tracked repository (public information). No Shipit session, API token, or repository write access to the victim repo is required — only the ability to send an HTTP POST to `/github/webhooks` with a correctly-signed body for the attacker's own org.

### Recommendation
- Verify the webhook signature independently of any attacker-supplied field, or, after verifying, cross-check that every repository/organization reference embedded in the payload (`repository.owner.login`, `repository.full_name`) matches the organization whose secret validated the signature; reject mismatches.
- Scope `StatusHandler` (and any other handler resolving records purely by external identifiers like `sha`) to the repository/stack indicated by the verified organization, not merely by a globally-unique-looking field such as commit SHA.

### Proof of Concept
1. Attacker administers `attacker-org`, which has the shared Shipit GitHub App installed, and knows `attacker-org`'s `webhook_secret` (from their own GitHub App/organization settings).
2. Attacker identifies a target commit SHA `deadbeef...` belonging to `victim-org/victim-repo`, tracked as a Stack on the same Shipit instance.
3. Attacker builds a `status` event JSON body:
```json
{
  "repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/attacker-repo"},
  "sha": "deadbeef...",
  "state": "success",
  "context": "ci/forged"
}
```
4. Attacker computes `X-Hub-Signature` using `attacker-org`'s webhook secret over this exact raw body and POSTs it to `WebhooksController#create` with `X-Github-Event: status`.
5. `verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and successfully verifies the HMAC against the attacker's own secret [1](#0-0) .
6. `StatusHandler#process` executes `Commit.where(sha: 'deadbeef...')`, which matches the commit in `victim-org/victim-repo`, and creates a forged `success` status on it [5](#0-4) , potentially triggering continuous delivery or PR auto-merge on the victim's stack.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L19-31)
```ruby
      return false unless stack.allows_merges?

      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
          ProcessMergeRequestsJob.set(wait: 10.seconds).perform_later(stack)
          return false
        end
      end
```

**File:** app/models/shipit/merge_request.rb (L164-191)
```ruby
    def merge!
      raise InvalidTransition unless pending?

      raise NotReady if not_mergeable_yet?

      stack.github_api.merge_pull_request(
        stack.github_repo_name,
        number,
        merge_message,
        sha: head.sha,
        commit_message: 'Merged by Shipit',
        merge_method: stack.merge_method
      )
      begin
        if stack.github_api.pull_requests(stack.github_repo_name, base: branch).empty?
          stack.github_api.delete_branch(stack.github_repo_name, branch)
        end
      rescue Octokit::UnprocessableEntity
        # branch was already deleted somehow
      end
      complete!
      true
    rescue Octokit::MethodNotAllowed # merge conflict
      reject!('merge_conflict')
      false
    rescue Octokit::Conflict # shas didn't match, PR was updated.
      raise NotReady
    end
```
