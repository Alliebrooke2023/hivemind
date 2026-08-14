# frozen_string_literal: true

require "rails_helper"

RSpec.describe Agents::EffortTier do
  let(:agent) { build_stubbed(:agent, effort: "standard") }

  describe ".valid?" do
    it "accepts every defined tier name" do
      described_class::NAMES.each { |name| expect(described_class.valid?(name)).to be true }
    end

    it "rejects unknown names" do
      expect(described_class.valid?("turbo")).to be false
      expect(described_class.valid?(nil)).to be false
    end
  end

  describe ".profile" do
    it "falls back to the default tier for unknown names rather than raising" do
      expect(described_class.profile("nope")).to eq(described_class.profile("standard"))
    end
  end

  describe ".resolve" do
    it "uses the agent's configured effort" do
      agent = build_stubbed(:agent, effort: "deep")
      expect(described_class.resolve(agent: agent)).to eq("deep")
    end

    it "prefers a session override over the agent default" do
      agent = build_stubbed(:agent, effort: "quick")
      session = build_stubbed(:session, metadata: { "effort" => "max" })
      expect(described_class.resolve(agent: agent, session: session)).to eq("max")
    end

    it "prefers an explicit argument over both" do
      agent = build_stubbed(:agent, effort: "quick")
      session = build_stubbed(:session, metadata: { "effort" => "max" })
      expect(described_class.resolve(agent: agent, session: session, effort: "deep")).to eq("deep")
    end

    it "falls back to the default when the agent has no effort set" do
      agent = build_stubbed(:agent, effort: nil)
      expect(described_class.resolve(agent: agent)).to eq("standard")
    end

    it "ignores an invalid override instead of propagating it" do
      expect(described_class.resolve(agent: agent, effort: "ludicrous")).to eq("standard")
    end

    it "tolerates a session whose metadata is nil" do
      session = build_stubbed(:session, metadata: nil)
      expect(described_class.resolve(agent: agent, session: session)).to eq("standard")
    end
  end

  describe ".loop_timeout_seconds" do
    it "returns the tier's own ceiling when no env override is set" do
      expect(described_class.loop_timeout_seconds("quick", env_override: nil)).to eq(60)
      expect(described_class.loop_timeout_seconds("max", env_override: nil)).to eq(1_800)
    end

    it "never exceeds an operator-set TOOL_LOOP_TIMEOUT" do
      expect(described_class.loop_timeout_seconds("max", env_override: "120")).to eq(120)
    end

    it "keeps the tier value when it is already below the operator limit" do
      expect(described_class.loop_timeout_seconds("quick", env_override: "600")).to eq(60)
    end
  end

  describe ".thinking_for" do
    it "forces thinking off on quick even when the agent enables it" do
      agent = build_stubbed(:agent, thinking_enabled: true, thinking_budget_tokens: 20_000)
      expect(described_class.thinking_for(agent, "quick")).to eq(enabled: false, budget_tokens: 0)
    end

    it "forces thinking on for deep, using the tier budget" do
      agent = build_stubbed(:agent, thinking_enabled: false, thinking_budget_tokens: 0)
      result = described_class.thinking_for(agent, "deep")
      expect(result[:enabled]).to be true
      expect(result[:budget_tokens]).to eq(10_000)
    end

    it "keeps a larger agent budget rather than lowering it" do
      agent = build_stubbed(:agent, thinking_enabled: true, thinking_budget_tokens: 64_000)
      expect(described_class.thinking_for(agent, "deep")[:budget_tokens]).to eq(64_000)
    end

    it "inherits the agent's own setting on standard" do
      enabled = build_stubbed(:agent, thinking_enabled: true, thinking_budget_tokens: 12_000)
      disabled = build_stubbed(:agent, thinking_enabled: false, thinking_budget_tokens: 0)

      expect(described_class.thinking_for(enabled, "standard")).to eq(enabled: true, budget_tokens: 12_000)
      expect(described_class.thinking_for(disabled, "standard")[:enabled]).to be false
    end
  end

  describe ".clamp_model_tier" do
    it "caps everything at cheap on quick" do
      expect(described_class.clamp_model_tier("top", "quick")).to eq("cheap")
      expect(described_class.clamp_model_tier("mid", "quick")).to eq("cheap")
    end

    it "leaves task detection untouched on standard" do
      %w[cheap mid top].each do |tier|
        expect(described_class.clamp_model_tier(tier, "standard")).to eq(tier)
      end
    end

    it "raises the floor to mid on deep but still allows top" do
      expect(described_class.clamp_model_tier("cheap", "deep")).to eq("mid")
      expect(described_class.clamp_model_tier("top", "deep")).to eq("top")
    end

    it "pins to top on max" do
      expect(described_class.clamp_model_tier("cheap", "max")).to eq("top")
    end

    it "treats an unrecognized detected tier as mid" do
      expect(described_class.clamp_model_tier("bogus", "standard")).to eq("mid")
    end
  end

  describe ".select_options" do
    it "returns [label, name] pairs for every tier" do
      expect(described_class.select_options).to eq([
        [ "Quick", "quick" ], [ "Standard", "standard" ], [ "Deep", "deep" ], [ "Max", "max" ]
      ])
    end
  end
end
