# frozen_string_literal: true

require "rails_helper"

RSpec.describe Agent, "effort tiers" do
  describe "validation" do
    it "accepts every defined tier" do
      Agents::EffortTier::NAMES.each do |name|
        expect(build(:agent, effort: name)).to be_valid
      end
    end

    it "rejects an unknown tier" do
      agent = build(:agent, effort: "ludicrous")
      expect(agent).not_to be_valid
      expect(agent.errors[:effort]).to be_present
    end

    it "allows blank so existing rows and imports don't break" do
      expect(build(:agent, effort: nil)).to be_valid
    end
  end

  describe "#effective_tool_loop_config" do
    it "reproduces the historical defaults on standard" do
      agent = build_stubbed(:agent, effort: "standard", tool_loop_config: {})
      config = agent.effective_tool_loop_config

      expect(config[:history_size]).to eq(Agent::DEFAULT_LOOP_CONFIG[:history_size])
      expect(config[:warning_threshold]).to eq(Agent::DEFAULT_LOOP_CONFIG[:warning_threshold])
      expect(config[:critical_threshold]).to eq(Agent::DEFAULT_LOOP_CONFIG[:critical_threshold])
      expect(config[:circuit_breaker_threshold]).to eq(Agent::DEFAULT_LOOP_CONFIG[:circuit_breaker_threshold])
    end

    it "tightens the leash on quick" do
      agent = build_stubbed(:agent, effort: "quick", tool_loop_config: {})
      config = agent.effective_tool_loop_config

      expect(config[:history_size]).to eq(12)
      expect(config[:circuit_breaker_threshold]).to eq(12)
    end

    it "loosens it on max" do
      agent = build_stubbed(:agent, effort: "max", tool_loop_config: {})
      config = agent.effective_tool_loop_config

      expect(config[:history_size]).to eq(80)
      expect(config[:circuit_breaker_threshold]).to eq(250)
    end

    it "lets an explicit per-agent override win over the tier" do
      agent = build_stubbed(:agent, effort: "quick", tool_loop_config: { "history_size" => 99 })
      config = agent.effective_tool_loop_config

      expect(config[:history_size]).to eq(99)
      # untouched keys still come from the tier
      expect(config[:circuit_breaker_threshold]).to eq(12)
    end

    it "honors a session override" do
      agent = build_stubbed(:agent, effort: "standard", tool_loop_config: {})
      session = build_stubbed(:session, metadata: { "effort" => "max" })

      expect(agent.effective_tool_loop_config(session: session)[:history_size]).to eq(80)
    end

    it "preserves detector settings from DEFAULT_LOOP_CONFIG" do
      agent = build_stubbed(:agent, effort: "deep", tool_loop_config: {})
      expect(agent.effective_tool_loop_config[:detectors][:generic_repeat]).to be true
    end
  end

  describe "#effective_effort" do
    it "reflects the resolution chain" do
      agent = build_stubbed(:agent, effort: "quick")
      session = build_stubbed(:session, metadata: { "effort" => "deep" })

      expect(agent.effective_effort).to eq("quick")
      expect(agent.effective_effort(session: session)).to eq("deep")
      expect(agent.effective_effort(session: session, effort: "max")).to eq("max")
    end
  end
end
