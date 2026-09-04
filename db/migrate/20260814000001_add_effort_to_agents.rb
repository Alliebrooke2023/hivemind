# frozen_string_literal: true

class AddEffortToAgents < ActiveRecord::Migration[8.1]
  def change
    # "standard" reproduces the pre-existing hardcoded defaults exactly, so
    # backfilling every current agent to it is a behavioral no-op.
    add_column :agents, :effort, :string, default: "standard", null: false
    add_index :agents, :effort
  end
end
