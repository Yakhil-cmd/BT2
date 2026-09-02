### Title
Webhook signature is validated for the organization named in `repository.owner.login`, but events are applied to the repository named by the independent `repository.full_name` field, enabling cross-organization webhook forgery — (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to check the `X-Hub-Signature` against using `repository_owner`, a value read directly out of the untrusted JSON body. Every webhook handler, however, resolves the actual `Repository`/`Stack` to act on using a different field from the same body: `repository.full_name`. Because these are two independent, attacker-controlled keys inside a single self-signed payload, an operator of one organization's legitimately configured GitHub App (a supported multi-org Shipit deployment) can sign a payload with their own valid secret while targeting a completely different organization's repository.

### Finding Description
`verify_signature` picks the app/secret purely from payload content, before any cryptographic check is performed: [1](#0-0) [2](#0-1) 

The `Shipit.github(organization: repository_owner)` call resolves to a `GithubApp`/`GithubOrganizationApp` instance whose `webhook_secret` comes from `config/secrets.yml`; in the documented multi-org configuration, each organization has its own independently configured `webhook_secret`: [3](#0-2) 

`verify_webhook_signature` only proves the raw body was HMAC-signed with *the secret selected by `repository_owner`* — it says nothing about which repository the rest of the payload actually names: [4](#0-3) 

Every handler (push, status, check_suite) instead resolves the target stack via `repository.full_name`, a sibling key that is never cross-checked against `repository.owner.login`: [5](#0-4) [6](#0-5) 

The `status` handler persists webhook-body fields (`state`, `description`, `target_url`, `context`) directly onto the commit's `Status` record without re-fetching from the GitHub API, as confirmed by the existing test asserting the stored status equals the raw payload values: [7](#0-6) 

So the binding that should hold is: `organization that authenticated == organization that owns the repository being written`. Instead the code enforces: `organization that authenticated == params.dig('repository','owner','login')` while writing to `Repository.from_github_repo_name(payload.dig('repository','full_name'))`, which can name any tracked repository regardless of the signing organization.

### Impact Explanation
An attacker who is a legitimate admin/owner of one organization's GitHub App configured in a multi-org Shipit instance (and therefore knows that org's own `webhook_secret`, which is not a secret belonging to the victim) can:
1. Sign a JSON body with their own org's secret (`repository.owner.login = "attacker-org"`).
2. Set `repository.full_name = "victim-org/victim-repo"` to target a stack they do not control.
3. Send a `status` event with `state: "success"` for a specific commit sha in the victim's repository, or a `push` event to force a resync.

Because `Handler#repository_name` is driven by `full_name`, the forged status is written onto the victim commit. This forged status can satisfy `all_status_checks_passed?` / clear `any_status_checks_missing?` / `any_status_checks_failed?`, which gate `MergeRequest#reject_unless_mergeable!` and `MergeRequest#merge!`, and gate deploy safety checks generally. This can enable an **unauthorized merge or deploy** for a stack/repository the attacker has no legitimate access to — a Critical-tier impact per the defined impact categories (unauthorized deploy/merge, escalation into authorization boundaries). [8](#0-7) [9](#0-8) 

### Likelihood Explanation
This requires a Shipit deployment configured with multiple GitHub organizations (a documented, supported configuration), and the attacker must control (or be an authorized admin of) at least one of those configured GitHub Apps — not the victim's. This is a realistic scenario for shared/multi-tenant Shipit instances serving several teams/orgs, where org boundaries are exactly the trust boundary Shipit is meant to enforce between tenants. No victim secret, session, or repository write access is required — only the attacker's own legitimate, lower-privileged org credentials.

### Recommendation
In `WebhooksController#verify_signature`, after selecting the app to verify against, re-derive the organization strictly from `repository.full_name` (or `organization.login` for org-level events) and require it to match the organization actually used for signature verification, rejecting the request (422) on mismatch. Equivalently, `Webhooks::Handlers::Handler#repository_name` should be validated against the same `repository_owner` value that authenticated the request before any handler is dispatched.

### Proof of Concept
1. Configure two organizations in `config/secrets.yml` per `docs/setup.md`'s multi-org example (`OrgA`, `OrgB`), each with its own `webhook_secret` and its own tracked stacks.
2. As the (legitimate, lower-privileged) owner of `OrgA`'s GitHub App, craft a `status` event body:
   ```json
   {
     "sha": "<victim-commit-sha>",
     "state": "success",
     "context": "ci/required",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=...` using `OrgA`'s known `webhook_secret` over the raw body.
4. POST to `/webhooks` with header `X-Github-Event: status`.
5. `verify_signature` resolves `repository_owner => "OrgA"`, verifies successfully against `OrgA`'s secret; `StatusHandler` then resolves the target stack via `repository.full_name => "OrgB/victim-repo"` and writes a forged passing status onto the victim's commit, as shown by the equivalent existing test at [7](#0-6) , without ever validating that `OrgA` and `OrgB` are the same tenant.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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
