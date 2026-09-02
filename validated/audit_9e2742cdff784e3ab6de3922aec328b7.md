Found it — `StatusHandler#process` in `app/models/shipit/webhooks/handlers/status_handler.rb:20-24` resolves the commit purely by `sha` and applies the `state` from the payload to **every** `Commit` row matching that SHA, across all repositories/stacks in the Shipit instance, with no check that the SHA belongs to the repository the webhook's signature was verified against.

### Title
Webhook status events bound to `sha` are not scoped to the verified repository/organization, allowing cross-repository CI-status forgery - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a webhook by resolving `repository_owner` from the payload and checking the signature against that specific GitHub App/organization's `webhook_secret` [1](#0-0) . Once verified, the `status` event is dispatched to `StatusHandler#process`, which looks up commits **only by `sha`**, ignoring `repository_owner`/`repository.full_name` entirely, and writes a GitHub-reported CI state to every matching `Commit` regardless of which stack/repository it belongs to [2](#0-1) . The binding that should hold — "the organization/repository whose signature was verified equals the repository whose commit is being written" — is broken.

### Finding Description
`verify_signature` picks the GitHub App config to validate against using `repository_owner`, which itself is read straight out of the untrusted payload (`params.dig('repository','owner','login')`) [3](#0-2) . In a multi-org configuration (`Shipit.github_app_config`) different organizations have distinct `webhook_secret`s [4](#0-3) , so a signature check only proves the payload was signed by *some* configured organization's app — it says nothing about which specific commit/repository the payload's other fields refer to.

`StatusHandler` never re-validates that the `sha` it is about to update belongs to a repository owned by the organization that was authenticated:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [2](#0-1) 

Because git SHAs are content-addressed and frequently shared across forks/mirrors/monorepo copies (e.g. a vendored dependency, a mirrored branch, or a shared merge-base commit reachable in multiple Shipit-tracked stacks), an actor who controls one organization's legitimate, correctly-signed webhook delivery (e.g. by pushing a commit whose SHA collides with — or is deliberately reused/cherry-picked into — a commit tracked by a different, unrelated stack) can cause a `status` webhook, validly signed by their own org's `webhook_secret`, to write a `success` CI status onto a `Commit` row belonging to a completely different repository/stack that they do not control and were never authenticated for.

### Impact Explanation
`Commit#create_status_from_github!` directly creates a `Status` used by `Stack#merge_status`, the merge queue (`MergeRequest::StatusChecker`/`all_status_checks_passed?`), and continuous-deployment gating [5](#0-4) [6](#0-5) . Forging a passing status on a foreign stack's commit can unblock `merge_request.merge!`, which calls `stack.github_api.merge_pull_request(...)` — a merge performed with the Shipit installation's own GitHub credentials on a repository/organization the attacker was never authorized against [7](#0-6) , and can also unblock continuous-delivery deploys gated on the same status. This is an unauthorized cross-repository write/merge performed with the app's own GitHub credentials — squarely in the "Critical" impact bucket for cross-repository writes/unauthorized merge.

### Likelihood Explanation
Exploitation requires the attacker to control a legitimately configured GitHub organization/app in the same Shipit instance (to obtain a validly-signed delivery) and to engineer a SHA collision or SHA reuse between their own repository and the victim stack's tracked commits — this is nontrivial but not implausible in multi-tenant Shipit deployments tracking many stacks/forks/mirrors, and requires no privileged Shipit credentials, `ApiClient` token, or repository write access to the victim repo itself, satisfying the unprivileged-attacker requirement.

### Recommendation
`StatusHandler` (and other handlers keying purely off `sha`, e.g. `PushHandler`/`CheckSuiteHandler`) should scope the lookup by the authenticated `repository_owner`/`repository.full_name` from the same verified payload, e.g. resolving the target `Repository`/`Stack` first and then filtering `commit.stack_id` against it, rather than matching `sha` globally across all stacks.

### Proof of Concept
1. Attacker registers/operates GitHub organization `attacker-org`, which is configured in Shipit's multi-org `secrets.github` with its own `webhook_secret`.
2. Attacker crafts a commit in their own repository whose SHA matches (or is force-pushed/cherry-picked to equal) a SHA already tracked as an undeployed commit in a `victim-org/victim-repo` stack (achievable e.g. via an empty/no-op commit with identical tree+parents+metadata, or by mirroring a shared merge-base commit).
3. Attacker triggers (or has their CI trigger) a GitHub `status` webhook event with `state: success` for that SHA; GitHub signs it with `attacker-org`'s `webhook_secret`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `attacker-org`, verifies successfully with `attacker-org`'s secret [1](#0-0) .
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the matching commit row in `victim-org/victim-repo`'s stack, and writes a `success` status onto it, even though the request never touched `victim-org`'s credentials [2](#0-1) .
6. `victim-org/victim-repo`'s merge queue or continuous-delivery job later observes the forged passing status and merges/deploys.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/merge_request.rb (L164-185)
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
```

**File:** app/models/shipit/merge_request.rb (L193-197)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```

**File:** app/jobs/shipit/process_merge_requests_job.rb (L21-27)
```ruby
      merge_requests.select(&:pending?).each do |merge_request|
        merge_request.refresh!
        next unless merge_request.all_status_checks_passed?

        begin
          merge_request.merge!
        rescue MergeRequest::NotReady
```
