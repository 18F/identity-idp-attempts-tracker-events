# frozen_string_literal: true

require './app'
run LoginGov::IdpAttemptsTracker::Events.new
