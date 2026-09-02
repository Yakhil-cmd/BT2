### Title
Webhook signature is verified against the organization named in the payload while `StatusHandler` writes commit status to *any* commit matching the SHA, regardless of repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the HMAC secret to validate a webhook against by reading the *unverified* `repository.owner.login` (or `organization.login`) field out of the raw JSON body, then calls `Shipit.github(organization: repository_owner)` to fetch that org's `webhook_secret` for validation. [1](#0-0)  Once the signature check passes, `StatusHandler#process` writes a commit status by looking up `Commit.where(sha: params.sha)` — with no scoping to a repository or organization at all. [2](#0-1)  The `StatusHandler` params schema doesn't even declare a `repository` field as required. [3](#0-2) 

This breaks the binding: **organization whose secret authenticated the webhook == repository/stack whose state is written**. Shipit explicitly supports multi-org configuration (one `webhook_secret`/App per org sharing a single Shipit instance), as documented in `config/secrets.development.example.yml` and `docs/setup.md`. [4](#0-3) 

### Finding Description
For the `status` event, Shipit's contract with GitHub is: GitHub signs the payload with the secret belonging to the app/org that owns the target repository, and the payload's `repository.owner.login` should match that same org. The signature check in `verify_signature` assumes this invariant holds and merely re-derives which secret to check against from the payload itself:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

But nothing forces the rest of the payload to be consistent with `repository.owner.login`. Since the webhooks endpoint is a public, unauthenticated HTTP endpoint (only signature-gated), any attacker who legitimately administers *one* org that is configured on the same multi-tenant Shipit instance — and therefore knows that org's own `webhook_secret` (they created/received it for their own integration) — can HMAC-sign an arbitrary payload with that secret and set `repository.owner.login` to their own org so the correct (and only checked) secret is selected. Nothing then requires the payload's actual effect (`sha`, `state`, etc.) to target that org's repository.

`StatusHandler` compounds this: it resolves the target purely by commit SHA, globally, with no repository/stack scoping:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [6](#0-5) 

`create_status_from_github!` → `add_status` then schedules merges/deploys for *that commit's own stack* whenever the new status is `pending` or `success`:

```ruby
if previous_status.simple_state != new_status.simple_state
  if !already_deployed && (!new_status.pending? || previous_status.unknown?)
    Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
  end
  stack.schedule_merges if new_status.pending? || new_status.success?
end
``` [7](#0-6) 

`schedule_merges` → `ProcessMergeRequestsJob` re-evaluates all pending merge requests for that stack and, once `all_status_checks_passed?`, calls `merge_request.merge!`, which performs the actual GitHub merge using the *target stack's own* GitHub credentials:

```ruby
def merge!
  ...
  stack.github_api.merge_pull_request(
    stack.github_repo_name,
    number,
    merge_message,
    sha: head.sha,
    commit_message: 'Merged by Shipit',
    merge_method: stack.merge_method
  )
  ...
end
``` [8](#0-7) [9](#0-8) 

So an attacker who only controls org A's webhook secret can forge a `status` event that is authenticated as "from org A" but, because the handler never checks the repository, writes a passing CI status onto a commit belonging to org B's stack — and if that satisfies org B's merge-queue requirements, triggers an unauthorized merge (or unblocks continuous delivery/deploy) on org B's repository, using org B's own GitHub App credentials.

### Impact Explanation
This crosses a trust boundary explicitly called out as in-scope: "an organization that authenticated versus the repository that is written." It results in an **unauthorized merge/deploy on a repository the attacker does not control**, performed with the victim stack's legitimate GitHub credentials — squarely matching the Critical-tier impact "cross-repository writes... or an unauthorized deploy, rollback or merge." The attacker never needs a Shipit session, an `ApiClient` token, the victim org's `webhook_secret`, GitHub App private key, or any privileged account — only knowledge of the webhook secret for any one org hosted on the same shared Shipit instance (which is a normal, documented multi-org configuration), plus the target commit's SHA (typically public on GitHub, or observable via the target stack's public commit history/status pages).

### Likelihood Explanation
Exploitability is gated on: (1) the Shipit instance being configured for multiple GitHub organizations (a documented, supported configuration — `docs/setup.md`, `config/secrets.development.example.yml`), and (2) the attacker legitimately controlling one of those orgs (and thus its webhook secret) while targeting a different, more sensitive org/stack sharing the same instance. In such shared/multi-tenant deployments this is a realistic scenario (e.g., internal platform teams onboarding many business units to one Shipit instance with differing trust levels). It also requires the target stack to have merge-queue/continuous-deployment enabled and a matching commit SHA — a moderate additional constraint, but well within a persistent attacker's control since SHAs of interest are usually public.

### Recommendation
- Verify the webhook signature using the secret associated with the actual target resource, not a value pulled from the unauthenticated request body. Alternatively, require every event type's handler to independently confirm that the payload's declared repository/organization matches the org whose secret validated the signature.
- Have `StatusHandler` (and any other handler that doesn't already do so) scope its lookup to the repository named in a verified/consistent field (e.g. `Commit.joins(stack: :repository).where(sha: params.sha, repositories: { github_id: verified_repo_id })`) rather than a bare, cross-stack `Commit.where(sha:)`.
- Consider binding each `GithubHook`/webhook secret to the specific stack/repository it was issued for (as already modeled by `Shipit::GithubHook`) rather than resolving trust at the organization level when the payload content is not organization-scoped.

### Proof of Concept
1. Deploy Shipit configured for two GitHub orgs, `attacker-org` and `victim-org`, each with its own `webhook_secret` (per the documented multi-org `secrets.yml` schema). [4](#0-3) 
2. Attacker knows `attacker-org`'s `webhook_secret` (they administer that org's GitHub App integration).
3. Attacker learns the SHA of a commit on `victim-org`'s tracked repository that is currently pending a merge/status check (public GitHub commit info).
4. Attacker crafts a `status` event JSON body: `{"sha": "<victim-commit-sha>", "state": "success", "context": "<required-context>", "repository": {"owner": {"login": "attacker-org"}}}`, computes `X-Hub-Signature: sha1=HMAC(attacker-org-secret, body)`, and POSTs it to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner` to `attacker-org`, fetches `attacker-org`'s secret, and validates successfully because the attacker signed with the correct (their own) secret. [10](#0-9) 
6. `StatusHandler#process` finds the matching `Commit` purely by SHA (belonging to `victim-org`'s stack) and records the forged "success" status. [6](#0-5) 
7. If this satisfies the victim stack's required checks, `stack.schedule_merges` → `ProcessMergeRequestsJob` → `MergeRequest#merge!` merges the PR on `victim-org`'s repository using `victim-org`'s own GitHub App credentials. [7](#0-6) [8](#0-7)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** app/models/shipit/commit.rb (L379-384)
```ruby
      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L10-32)
```ruby
    def perform(stack)
      merge_requests = stack.merge_requests.to_be_merged.to_a
      merge_requests.each do |merge_request|
        merge_request.refresh!
        merge_request.reject_unless_mergeable!
        merge_request.cancel! if merge_request.closed?
        merge_request.revalidate! if merge_request.need_revalidation?
      end

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
    end
```
