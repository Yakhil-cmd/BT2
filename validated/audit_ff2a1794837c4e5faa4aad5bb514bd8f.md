### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but event handlers act on the (unvalidated) `repository.full_name` — a forged cross-repository status can trigger an unauthorized GitHub merge - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate the HMAC signature against using `repository.owner.login` (or `organization.login`) taken directly from the untrusted JSON body. [1](#0-0) [2](#0-1) 

Once the signature is accepted, every `Handler` subclass resolves the target `Stack`/`Repository` using a *different* field of the same payload: `repository.full_name`. [3](#0-2) 

Because `repository.owner.login` (used to pick the authenticating secret) and `repository.full_name` (used to pick the target repository/stack) are two independent JSON fields that are never cross-checked, an attacker who legitimately controls one GitHub organization/webhook secret configured in this Shipit instance can forge a signed payload whose signature validates against *their own* org while `repository.full_name` points at a *different* victim repository/stack also hosted on the same Shipit instance.

### Finding Description
Shipit supports hosting multiple GitHub organizations, each with its own `webhook_secret`, as documented in `config/secrets.development.example.yml`. [4](#0-3) 

`WebhooksController#verify_signature` derives the signing organization from the payload itself, not from any authenticated/independent source:
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

`verify_webhook_signature` just checks the HMAC of the raw POST body against whichever org's `webhook_secret` was picked:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  algorithm, signature = signature.split("=", 2)
  return false unless algorithm == 'sha1'
  SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
end
``` [6](#0-5) 

Every event handler, however, resolves the affected `Repository`/`Stack` using a *different* payload field — `repository.full_name` — which is never compared to `repository.owner.login`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 
This exact pattern (`Repository.from_github_repo_name(params.repository.full_name)`) is repeated across `pull_request/opened_handler.rb`, `closed_handler.rb`, `labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`, and `assigned_handler.rb`. [7](#0-6) 

The binding that should hold — `organization that authenticated the request == organization that owns the repository being written to` — is not enforced anywhere in the request-handling path. `repository.owner.login` and `repository.full_name` are sibling fields under the same attacker-controlled JSON object, and nothing forces `full_name`'s owner segment to equal `owner.login`.

The most severe consequence is in the `status` event flow: `StatusHandler` (per `Shipit::Webhooks::EVENTS`/handler registration, confirmed by `test/controllers/webhooks_controller_test.rb`'s `:status` tests) creates a `Status` record on a commit belonging to the `stacks` resolved from `repository.full_name`, using the state/context/target_url supplied directly in the payload. [8](#0-7) 
Those `Status` rows feed directly into `MergeRequest#all_status_checks_passed?`/`StatusChecker`, which gate `ProcessMergeRequestsJob`'s automatic `merge_request.merge!` call — an actual GitHub PR merge performed with Shipit's own `GITHUB_TOKEN`: [9](#0-8) [10](#0-9) [11](#0-10) 

### Impact Explanation
An attacker who is authorized to configure/know the `webhook_secret` for *one* GitHub organization hosted on a shared Shipit instance can sign a payload with that secret while setting `repository.full_name` to point at a *victim* repository/stack also on the same instance. Because handlers key exclusively off `full_name`, this forges: fake commit statuses (bypassing required CI checks and enabling `ProcessMergeRequestsJob` to auto-merge a PR that never actually passed CI — an unauthorized merge using Shipit's real GitHub credentials), fake push events (triggering `GithubSyncJob` against the victim stack), and fake pull_request lifecycle events (archiving/unarchiving/provisioning review stacks it does not control). This crosses the "unauthorized merge" bar defined as Critical impact.

### Likelihood Explanation
Exploitation requires the attacker to control the webhook secret of at least one organization configured on the Shipit instance — a realistic multi-tenant scenario explicitly supported and documented by this engine (`config/secrets.development.example.yml` shows the multi-org config shape). No GitHub App private key, Shipit session, or `ApiClient` token is required; only a raw HTTP POST to the public `/webhooks` endpoint with a correctly computed HMAC using the attacker's own known secret.

### Recommendation
Verify that `repository.owner.login` (the identity used to select the verifying secret) matches the owner segment of `repository.full_name` (the identity used to resolve the target `Repository`/`Stack`) before dispatching to any handler, rejecting the request otherwise. Alternatively, resolve the target `Repository` using the same organization value already used to select the webhook secret, rather than trusting `full_name` independently.

### Proof of Concept
1. Attacker controls organization `attacker-org`, configured in Shipit with `webhook_secret = S_attacker` (a normal, legitimate tenant of the Shipit instance).
2. Attacker crafts a JSON body for a `status` event:
```json
{
  "sha": "<victim PR head sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": {
    "full_name": "victim-org/victim-repo",
    "owner": { "login": "attacker-org" }
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S_attacker, body)>` and POSTs it to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature against `S_attacker`. [1](#0-0) 
5. The `status` handler resolves `stacks` via `payload.dig('repository','full_name')` = `"victim-org/victim-repo"`, and writes a forged `success` `Status` on the victim's commit. [3](#0-2) 
6. On the next `ProcessMergeRequestsJob` run for the victim stack, `all_status_checks_passed?` returns true for the forged status and `merge_request.merge!` merges the victim's pull request via GitHub using Shipit's real credentials — an unauthorized merge triggered entirely by an unrelated tenant. [12](#0-11) 

*Note: I was unable to load the full contents of `app/models/shipit/webhooks/handlers/status_handler.rb` and `push_handler.rb` from the index (size limits), so the exact field list they process could not be directly cited; the behavior is inferred from the shared `Handler#stacks`/`repository_name` base class (used identically by all confirmed handlers) and the `status`-event test coverage in `webhooks_controller_test.rb`. Starting a full Devin session would allow direct inspection of those two files to confirm the exact `Status` attributes taken from the payload.*

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/jobs/shipit/process_merge_requests_job.rb (L19-30)
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
```

**File:** app/models/shipit/merge_request.rb (L164-197)
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

    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end
```
