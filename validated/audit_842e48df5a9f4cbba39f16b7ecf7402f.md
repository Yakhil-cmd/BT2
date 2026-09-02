### Title
Webhook organization/signature check is decoupled from the repository the handler actually acts on, allowing cross-repository forged events - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
The AMM sandwich-attack report is a "binding break" bug class: a value the protocol trusts (the pre-trade price/slippage) is not the value actually enforced at settlement. The same class of bug exists in Shipit's webhook ingestion pipeline: the field used to select *which* organization's secret authenticates a webhook request is different from the field used to select *which repository/stack the resulting handler acts on*, and when the selected organization has no `webhook_secret` configured (an explicitly supported, documented state), verification is a complete no-op.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to validate against using `repository_owner`, taken from the attacker-supplied JSON body: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` treats an unconfigured `webhook_secret` as automatically valid: [3](#0-2) 

Shipit natively supports multiple GitHub organizations sharing one instance, each with its own independently-optional `webhook_secret` (`# nil` is a documented valid value): [4](#0-3) [5](#0-4) 

Once the request passes `verify_signature`, every event `Handler` determines which `Repository`/`Stack` to actually mutate using a *different* field of the same attacker-controlled JSON body — `repository.full_name` — with no cross-check that it matches the organization whose secret (or lack thereof) authorized the request: [6](#0-5) 

`PushHandler` (and by the same pattern, `status`, `pull_request`, `check_suite`, etc. handlers) then acts on whatever stacks match that claimed `full_name`: [7](#0-6) 

**Equality that should hold but doesn't**: `organization whose secret authenticated the request == owner of the repository the handler mutates`. Because `repository_owner` (verification key selector) and `repository.full_name` (mutation target selector) are two independent fields inside one JSON blob, and because verification is skipped entirely for any org without a `webhook_secret`, an attacker can pick an org with no secret configured (`repository.owner.login = "OrgWithNoSecret"`) purely to make `verify_signature` pass trivially, while setting `repository.full_name = "OrgWithSecret/protected-repo"` to direct the handler at a stack belonging to a completely different, secured organization.

Before the attacker's request: only genuine GitHub deliveries signed with `OrgWithSecret`'s HMAC key can affect `OrgWithSecret/protected-repo`'s stacks. After: any unauthenticated actor can drive the same handlers (`PushHandler#process` → `stack.sync_github`, status handlers feeding `Shipit::Status`, pull_request handlers touching `MergeRequest` state) against `OrgWithSecret/protected-repo`, because the signature check never actually binds `repository.full_name` to a verified secret — it only checks `repository.owner.login`, which is attacker-chosen and can point anywhere.

### Impact Explanation
The most severe path runs through fabricated `status` events. `Shipit::Status` records created by the webhook feed directly into `MergeRequest#all_status_checks_passed?`: [8](#0-7) 

which `ProcessMergeRequestsJob` uses to autonomously call `merge_request.merge!`, invoking `stack.github_api.merge_pull_request` with the app's own GitHub App installation credentials: [9](#0-8) [10](#0-9) 

By forging fake "success" status webhooks for a pull request under a repository the attacker does not control (using an unrelated, secret-less org login to pass `verify_signature`), an unprivileged remote actor can make Shipit believe CI passed and cause it to **merge that pull request using the app's own GitHub credentials** — an unauthorized merge/deploy, matching the report's Critical bar.

### Likelihood Explanation
Requires only: (1) knowledge that the target Shipit instance manages multiple GitHub organizations (visible from public config docs/behavior, e.g. `docs/setup.md`), and (2) that at least one configured organization has no `webhook_secret` set, which is an explicitly documented, first-class supported configuration (shown as `webhook_secret: # nil` in the shipped example secrets files). No credentials, GitHub App keys, or session are needed — only network access to `POST /webhooks`, matching the "unprivileged attacker" bar for this scan.

### Recommendation
- Verify the webhook HMAC using the same repository/organization identity that the handler will act on: re-derive the "trusted org" strictly from `repository.full_name`'s owner segment (not a separate `owner.login`/`organization.login` fallback field), and reject if they disagree.
- Do not silently accept unsigned payloads when `webhook_secret` is unset for one organization in a multi-org deployment; either require a secret for every configured organization or explicitly scope "no-secret" orgs so they cannot resolve to stacks belonging to other organizations.
- Add a check in `Shipit::Webhooks::Handlers::Handler#stacks` that the resolved `Repository`'s owner matches the organization actually verified in `verify_signature`.

### Proof of Concept
1. Deploy Shipit configured with two organizations: `OrgWithSecret` (has stacks, `webhook_secret` set) and `OrgNoSecret` (no `webhook_secret`, as permitted by `docs/setup.md`).
2. Attacker sends `POST /webhooks` with header `X-Github-Event: status`, no valid `X-Hub-Signature` for `OrgWithSecret`, and JSON body:
   ```json
   {
     "repository": { "owner": { "login": "OrgNoSecret" }, "full_name": "OrgWithSecret/protected-repo" },
     "sha": "<head sha of a pending PR>",
     "state": "success",
     "context": "ci/required-check"
   }
   ```
3. `verify_signature` calls `Shipit.github(organization: "OrgNoSecret")`; `verify_webhook_signature` returns `true` unconditionally because `OrgNoSecret` has no `webhook_secret` (`lib/shipit/github_app.rb:76-77`).
4. The status handler resolves the target stack via `repository.full_name` = `"OrgWithSecret/protected-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) and records a fake passing `Status` for the commit.
5. Once all required statuses appear to pass, `ProcessMergeRequestsJob` invokes `merge_request.merge!`, causing Shipit to merge the pull request in `OrgWithSecret/protected-repo` using the app's own GitHub credentials — without the attacker ever possessing `OrgWithSecret`'s webhook secret.

### Citations

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/merge_request.rb (L193-202)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end
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
