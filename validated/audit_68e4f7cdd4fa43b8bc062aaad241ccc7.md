### Title
Cross-tenant commit status forgery via unscoped `Commit.where(sha:)` lookup enables unauthorized deploy trigger - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The GitHub `status` webhook handler looks up commits to update purely by `sha`, with no scoping to the repository/organization that the webhook signature actually authenticated. Any org onboarded to Shipit (owned/controlled by an attacker) can send a validly-signed `status` webhook whose `sha` field is an arbitrary string chosen by the attacker, and if that string matches a commit SHA tracked by any *other* stack in the same Shipit instance, that victim commit's CI state is mutated, which can make it `deployable?` and get selected by `Stack#next_commit_to_deploy`, triggering `Stack#trigger_continuous_delivery`.

### Finding Description
The broken binding: the request is authenticated as belonging to `repository_owner` (via `Shipit.github(organization: repository_owner).verify_webhook_signature`, see [1](#0-0) ), but the effect of the request — which `Commit` rows get a new `Status` — is determined solely by `params.sha`, an attacker-controlled string in the JSON body, with **no check that the commit's `stack`/repository matches `repository_owner`**: [2](#0-1) 

So the intended equality `authenticated_repository == commit.stack.repository` is never enforced; only `authenticated_org == repository_owner_in_payload` is checked, and `sha` is unconstrained free text (`requires :sha, String`) rather than being tied to any commit belonging to that org's repositories.

Exploit flow:
1. Attacker owns/controls a GitHub organization/repo that is a legitimate Shipit tenant (has its own `webhook_secret` configured, since Shipit supports "Using Multiple Github Applications" per org, see [3](#0-2) ), or otherwise can produce a request whose `repository.owner.login`/`organization.login` resolves to an org that authenticates successfully.
2. Attacker POSTs to `/webhooks` with `X-Github-Event: status`, a valid `X-Hub-Signature` computed with their own org's `webhook_secret`, and a JSON body containing `sha: "<victim-commit-sha>"`, `state: "success"`, `repository.owner.login: "<attacker-org>"`.
3. `WebhooksController#verify_signature` succeeds because the signature matches the attacker's own configured secret for their own org: [4](#0-3) .
4. `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, matching any commit across the entire Shipit database (any stack, any repository) with that SHA — including the victim's commit in a completely different repository.
5. `Commit#create_status_from_github!` -> `Commit#add_status` creates a `Status` row and, per `Status#schedule_continuous_delivery`, schedules continuous delivery for the victim's stack: [5](#0-4) .
6. If the victim stack has `blocking_statuses` empty (default), `Commit#blocked?` short-circuits to `false` without querying anything: [6](#0-5) , so `Commit#deployable?` becomes `true` purely off the forged `success?` status: [7](#0-6) .
7. `Stack#next_expected_commit_to_deploy`/`next_commit_to_deploy` will pick this now-"deployable" commit: [8](#0-7) , and continuous delivery triggers a real deploy on victim infrastructure.

Existing guards do not stop this: `verify_signature` only validates that the *sender* controls a valid org secret — it says nothing about which commits that sender is allowed to affect. There is no `stack_id`/`repository` cross-check anywhere in `StatusHandler`, unlike, e.g., push handling which uses `stack.repository`-scoped lookups. The `branches` field accepted in the `StatusHandler` params schema is never actually used to filter/restrict which commits are touched, so it provides no protection either: [9](#0-8) .

### Impact Explanation
A payload correctly signed for one tenant/organization mutates commit/CI state belonging to a completely unrelated stack/repository, and can trigger an unauthorized deploy on that victim's infrastructure — this matches the Critical category "a payload for one repository mutating another's stack, commit, task or team... or an unauthorized deploy." The blast radius spans every stack in the Shipit instance: any attacker who can authenticate as *any* onboarded org (even their own) can forge statuses for commits in *any other* stack, provided a SHA match. This is repeatable per victim commit and does not require compromising any Shipit or GitHub secret belonging to the victim.

### Likelihood Explanation
Preconditions: the attacker needs (a) a Shipit-recognized organization for which they can produce validly-signed webhook traffic — realistic under the documented multi-org configuration where webhook secrets are per-org rather than per-Shipit-instance, and (b) knowledge of a victim commit SHA (public on GitHub for public repos, or leaked/observed for private ones) that is tracked in a victim `Stack`, and (c) `blocking_statuses` empty (the default) so `Commit#blocked?` never queries upstream CI truth. No privileged Shipit role, session, or API token is required. This is a low-cost, repeatable attack: a single crafted HTTP POST per targeted commit.

### Recommendation
Scope the `StatusHandler#process` lookup to commits belonging to stacks whose repository matches the authenticated `repository_owner`/`repository.full_name` from the payload (e.g., `Commit.joins(:stack).merge(Stack.where(repository: matching_repo)).where(sha: params.sha)`), rather than a bare `Commit.where(sha: params.sha)` across the entire installation.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, or a model-level test with a controller test asserting a Deploy is created):
```ruby
test "status webhook for org A cannot forge a status for a commit belonging to org B's stack" do
  victim_stack = shipit_stacks(:shipit) # repository owned by "shopify", blocking_statuses empty
  victim_commit = shipit_commits(:some_pending_commit) # currently unknown/pending state on victim_stack
  victim_commit.stack.update!(continuous_deployment: true)

  refute_predicate victim_commit, :deployable? # baseline: not deployable pre-attack

  attacker_org = "attacker-org" # a distinct, independently configured Shipit tenant
  forged_payload = {
    "sha" => victim_commit.sha,
    "state" => "success",
    "context" => "ci/travis",
    "repository" => { "owner" => { "login" => attacker_org } }
  }.to_json

  request.headers['X-Github-Event'] = 'status'
  # signed with attacker_org's own webhook_secret, not the victim's
  Shipit.github(organization: attacker_org).stubs(:verify_webhook_signature).returns(true)

  assert_difference -> { victim_commit.statuses.count }, 1 do
    post :create, body: forged_payload, as: :json
  end

  victim_commit.reload
  assert_predicate victim_commit, :success?
  assert_predicate victim_commit, :deployable? # attacker-forged status now makes victim's commit deployable

  assert_enqueued_with(job: Shipit::ContinuousDeliveryJob, args: [stack_id: victim_stack.id]) do
    # or directly assert a Deploy record gets created when continuous delivery job runs
  end
end
```
This demonstrates that a status webhook authenticated for one organization mutates and unlocks deployability of a commit belonging to a completely different, victim stack, with no legitimate CI status ever posted by the victim's own CI/webhook.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/status.rb (L18-44)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit

    class << self
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
    end

    private

    def enable_ci_on_stack
      commit.stack.enable_ci!
    end

    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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

**File:** app/models/shipit/stack.rb (L332-342)
```ruby
    def next_expected_commit_to_deploy(commits: nil)
      commits ||= undeployed_commits do |scope|
        scope.preload(:statuses, :check_runs)
      end

      commits_to_deploy = commits.reject(&:active?)
      if maximum_commits_per_deploy
        commits_to_deploy = commits_to_deploy.reverse.slice(0, maximum_commits_per_deploy).reverse
      end
      commits_to_deploy.find(&:deployable?)
    end
```
