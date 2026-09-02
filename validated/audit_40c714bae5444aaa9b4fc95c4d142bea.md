### Title
Webhook signature is verified against the payload's `repository.owner.login`/organization while every handler dispatches on the independently-controlled `repository.full_name` field, letting any org-authenticated webhook sender forge Status/Push/PullRequest events for stacks belonging to a different GitHub organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to check the HMAC against based on `repository_owner`, derived from `params.dig('repository','owner','login')` (falling back to `organization.login`). [1](#0-0)  Every event handler, however, resolves *which stack/repository to act on* using a completely different JSON field in the same payload: `payload.dig('repository', 'full_name')`. [2](#0-1)  Since GitHub payload JSON keys are not cross-validated against each other, an attacker who legitimately controls the webhook secret for organization "A" can build a JSON body where `repository.owner.login = "A"` (so the signature check passes with A's secret) but `repository.full_name = "victim-org/victim-repo"` (so the handler acts on the victim's stack). This breaks the intended binding "organization that authenticated == repository being written."

### Finding Description
`verify_signature` computes: `github_app = Shipit.github(organization: repository_owner)` then `github_app.verify_webhook_signature(signature, raw_post)`. [3](#0-2)  `repository_owner` is read straight from the untrusted payload body (`repository.owner.login` or `organization.login`), i.e., it is attacker-controlled input used only to pick the *secret* to validate against, not to constrain what the payload may claim afterward. [4](#0-3) 

Downstream, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full, already-parsed JSON to handlers such as `PushHandler`, `StatusHandler`, and the `PullRequest::*` handlers. [5](#0-4)  All of these inherit `Handler#stacks`/`#repository_name`, which look up the target `Repository` via `payload.dig('repository', 'full_name')`, entirely independent of `repository.owner.login`: [2](#0-1)  `Repository.from_github_repo_name` then splits `owner/name` from that same `full_name` field to find the DB record to act on. [6](#0-5) 

Because Shipit explicitly supports hosting multiple GitHub organizations from a single deployment (each with its own `webhook_secret` in `config/secrets.yml`), [7](#0-6)  an attacker who is a legitimate GitHub App owner/admin for organization "bobcorp" (one tenant configured on the shared instance) knows `bobcorp`'s own `webhook_secret`. They can POST directly to `/webhooks` (bypassing GitHub entirely) with:
- `repository.owner.login = "bobcorp"` (satisfies the org lookup and signature check, since Bob knows this secret)
- `repository.full_name = "victim-org/victim-repo"` (used by every handler to select which stack to mutate)
- HMAC-SHA1 signature computed by Bob himself over this exact body using `bobcorp`'s secret

`verify_signature` passes because the signature is valid for the secret selected by the (attacker-chosen) `repository_owner` field; nothing re-checks that `full_name`'s owner segment matches `repository_owner`.

### Impact Explanation
With a forged `status` event, `StatusHandler#process` calls `Commit#create_status_from_github!(params)` for any commit `sha` belonging to `victim-org/victim-repo`'s stacks. [8](#0-7)  Forged CI/status data is exactly the signal `MergeRequest::StatusChecker` and `Stack#merge_status` rely on to decide whether commits are deployable/mergeable [9](#0-8) , and `MergeRequest#merge!` performs `stack.github_api.merge_pull_request(...)` once required checks report success. [10](#0-9)  An attacker who is merely a legitimate tenant admin on one organization of a shared Shipit instance can therefore inject fabricated "success" statuses for another organization's commits, driving Shipit's merge queue to auto-merge pull requests on a repository they have no GitHub write access to - an unauthorized cross-repository merge using the app's own `GITHUB_TOKEN`/installation credentials. This satisfies the Critical impact bar ("cross-repository writes ... an unauthorized deploy, rollback or merge").

Forged `push` events similarly cause `PushHandler` to trigger `stack.sync_github(expected_head_sha:)` against the victim's stack, and forged `pull_request`/`membership` events let the attacker create/archive review stacks or manipulate team membership scoped to the victim org, all while authenticating only as their own tenant.

### Likelihood Explanation
This requires the attacker to control a legitimately configured GitHub App/organization on a Shipit deployment that hosts multiple organizations (a documented, supported configuration), but no privileged Shipit session, `ApiClient` token, or the victim's own webhook secret. This is a plausible operator scenario for any shared/multi-tenant Shipit install (e.g., an internal platform team onboarding several business units), where "authenticated as org A" is wrongly treated as sufficient authorization to name and mutate any `repository.full_name`.

### Recommendation
In `WebhooksController#verify_signature`/`Handler`, cross-validate that the `repository.owner.login` (or `organization.login`) used to select the signing secret is identical to the owner segment parsed from `repository.full_name` before dispatching to any handler; reject the request (422) on mismatch. Alternatively, derive the repository/stack strictly from the same field that was used for authentication (`repository.owner.login` + `repository.name`), rather than trusting `full_name` independently in `Handler#repository_name`.

### Proof of Concept
1. Shipit is configured with `config/secrets.yml` `github:` containing both `bobcorp` (attacker-controlled organization, admin knows its `webhook_secret`) and `victim-org` per the documented multi-org setup. [7](#0-6) 
2. Attacker crafts a `status` webhook JSON body:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/required-check",
     "repository": {
       "owner": { "login": "bobcorp" },
       "full_name": "victim-org/victim-repo"
     }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(bobcorp_webhook_secret, body)` themselves and POSTs to `/webhooks` with header `X-Github-Event: status`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "bobcorp")` and successfully verifies the signature using the attacker's own known secret. [3](#0-2) 
5. `StatusHandler` resolves the target commit/stack via `full_name = "victim-org/victim-repo"` (ignoring `bobcorp`) and records a forged successful status on the victim's commit. [8](#0-7) [2](#0-1) 
6. If `victim-org/victim-repo`'s stack has `merge_queue_enabled` and the forged status satisfies `merge_request_required_statuses`, Shipit's merge queue subsequently calls `MergeRequest#merge!`, which invokes `stack.github_api.merge_pull_request(...)` - an unauthorized cross-repository merge performed with Shipit's own GitHub credentials. [10](#0-9)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** docs/setup.md (L182-209)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/merge_request.rb (L164-176)
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
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```
