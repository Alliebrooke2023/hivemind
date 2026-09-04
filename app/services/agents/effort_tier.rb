# frozen_string_literal: true

module Agents
  # Quantizes agent reasoning effort into a small set of named tiers.
  #
  # Without this, "how hard should the agent think?" is spread across four
  # unrelated knobs — model choice, thinking budget, tool-call ceiling, and
  # wall-clock timeout — each set independently per agent. A tier bundles them
  # into one dial, so "this agent drafts changelog entries" and "this agent
  # designs migrations" become a single choice instead of four correlated ones.
  #
  # Resolution order (first match wins):
  #   1. explicit `effort:` argument (a one-off override for this run)
  #   2. session metadata["effort"] (per-conversation override)
  #   3. agent.effort (the agent's configured default)
  #   4. DEFAULT ("standard")
  #
  # The tier is a *baseline*, not a mandate. `Agent#effective_tool_loop_config`
  # deep-merges an agent's explicit `tool_loop_config` on top of the tier's
  # values, so hand-tuned agents keep their settings.
  #
  # STANDARD is deliberately identical to the historical hardcoded defaults
  # (Agent::DEFAULT_LOOP_CONFIG and ToolLoop's 300s timeout), so existing
  # agents behave exactly as they did before this dial existed.
  module EffortTier
    DEFAULT = "standard"

    # Model tiers, weakest to strongest. Mirrors Agents::ModelRouter's tiers.
    MODEL_TIER_RANK = { "cheap" => 0, "mid" => 1, "top" => 2 }.freeze

    # :inherit — leave the agent's own thinking settings alone
    # :off     — force thinking off regardless of agent config
    # :on      — force thinking on, with at least the tier's budget
    TIERS = {
      "quick" => {
        label: "Quick",
        description: "Cheap model, no extended thinking, short leash. Triage, " \
                     "formatting, status checks, anything you'd rather have " \
                     "answered in seconds than perfectly.",
        model_tier_ceiling: "cheap",
        model_tier_floor: nil,
        thinking: :off,
        thinking_budget_tokens: 0,
        loop_timeout_seconds: 60,
        tool_loop_config: {
          history_size: 12,
          warning_threshold: 4,
          critical_threshold: 8,
          circuit_breaker_threshold: 12
        },
        context_budget_tokens: 2_000
      },
      "standard" => {
        label: "Standard",
        description: "Balanced default. Model chosen by task detection, " \
                     "thinking left to the agent's own setting. Matches " \
                     "Hivemind's behavior before effort tiers existed.",
        model_tier_ceiling: nil,
        model_tier_floor: nil,
        thinking: :inherit,
        thinking_budget_tokens: nil,
        loop_timeout_seconds: 300,
        tool_loop_config: {
          history_size: 30,
          warning_threshold: 10,
          critical_threshold: 20,
          circuit_breaker_threshold: 100
        },
        context_budget_tokens: 4_000
      },
      "deep" => {
        label: "Deep",
        description: "Stronger model floor, extended thinking on, room to " \
                     "explore before answering. Multi-file changes, debugging, " \
                     "design work.",
        model_tier_ceiling: nil,
        model_tier_floor: "mid",
        thinking: :on,
        thinking_budget_tokens: 10_000,
        loop_timeout_seconds: 900,
        tool_loop_config: {
          history_size: 50,
          warning_threshold: 20,
          critical_threshold: 40,
          circuit_breaker_threshold: 150
        },
        context_budget_tokens: 8_000
      },
      "max" => {
        label: "Max",
        description: "Top model always, large thinking budget, long leash. " \
                     "Architecture, security review, migrations — jobs where " \
                     "a wrong answer costs more than the tokens.",
        model_tier_ceiling: nil,
        model_tier_floor: "top",
        thinking: :on,
        thinking_budget_tokens: 32_000,
        loop_timeout_seconds: 1_800,
        tool_loop_config: {
          history_size: 80,
          warning_threshold: 30,
          critical_threshold: 60,
          circuit_breaker_threshold: 250
        },
        context_budget_tokens: 16_000
      }
    }.freeze

    NAMES = TIERS.keys.freeze

    class << self
      def valid?(name)
        NAMES.include?(name.to_s)
      end

      # @return [Hash] the frozen tier definition, falling back to DEFAULT
      #   for nil/unknown names so a bad value can never break a chat turn.
      def profile(name)
        TIERS.fetch(name.to_s) { TIERS.fetch(DEFAULT) }
      end

      # Resolves which tier applies for this turn.
      #
      # @param agent [Agent]
      # @param session [Session, nil]
      # @param effort [String, nil] explicit one-off override
      # @return [String] a name guaranteed to be in NAMES
      def resolve(agent:, session: nil, effort: nil)
        candidate = effort.presence ||
                    session_effort(session) ||
                    agent&.effort.presence ||
                    DEFAULT

        valid?(candidate) ? candidate.to_s : DEFAULT
      end

      # @return [Hash] resolved tier profile for this turn
      def resolve_profile(agent:, session: nil, effort: nil)
        profile(resolve(agent:, session:, effort:))
      end

      # Wall-clock ceiling for the tool loop, in seconds.
      #
      # TOOL_LOOP_TIMEOUT stays authoritative when an operator has set it —
      # it's an infrastructure guard (don't hold a Sidekiq thread too long),
      # and tiers must not let an agent exceed an operator's limit.
      def loop_timeout_seconds(name, env_override: ENV["TOOL_LOOP_TIMEOUT"])
        tier_value = profile(name)[:loop_timeout_seconds]
        return tier_value if env_override.blank?

        [ tier_value, env_override.to_i ].min
      end

      # Thinking settings for this tier applied to a given agent.
      #
      # @return [Hash] { enabled: Boolean, budget_tokens: Integer }
      def thinking_for(agent, name)
        tier = profile(name)
        agent_budget = agent&.thinking_budget_tokens.to_i

        case tier[:thinking]
        when :off
          { enabled: false, budget_tokens: 0 }
        when :on
          { enabled: true, budget_tokens: [ agent_budget, tier[:thinking_budget_tokens].to_i ].max }
        else
          { enabled: !!agent&.thinking_enabled?, budget_tokens: agent_budget.positive? ? agent_budget : 10_000 }
        end
      end

      # Clamps a task-detected model tier into the band this effort tier allows.
      #
      # Effort constrains rather than dictates: "deep" raises the floor to mid
      # but still lets task detection pick top, while "quick" caps everything
      # at cheap. That keeps ModelRouter's task signal meaningful instead of
      # overriding it wholesale.
      #
      # @param detected_tier [String] "cheap" | "mid" | "top"
      # @return [String] the clamped tier
      def clamp_model_tier(detected_tier, name)
        tier = profile(name)
        rank = MODEL_TIER_RANK[detected_tier.to_s] || MODEL_TIER_RANK["mid"]

        if (floor = tier[:model_tier_floor])
          rank = [ rank, MODEL_TIER_RANK.fetch(floor) ].max
        end

        if (ceiling = tier[:model_tier_ceiling])
          rank = [ rank, MODEL_TIER_RANK.fetch(ceiling) ].min
        end

        MODEL_TIER_RANK.key(rank)
      end

      # Options for the UI select: [["Quick — cheap model, …", "quick"], …]
      def select_options
        TIERS.map { |name, tier| [ tier[:label], name ] }
      end

      private

      def session_effort(session)
        return nil unless session.respond_to?(:metadata)

        value = session.metadata.is_a?(Hash) ? (session.metadata["effort"] || session.metadata[:effort]) : nil
        value.presence
      end
    end
  end
end
