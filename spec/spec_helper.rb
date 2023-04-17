# frozen_string_literal: true

require 'bosh/template/test'

module SharedContext
  extend RSpec::SharedContext

  let(:release_path) { File.join(File.dirname(__FILE__), '..') }
  let(:release) { Bosh::Template::Test::ReleaseDir.new(release_path) }
  let(:pcap_api_job) { release.job('pcap-api') }
  let(:pcap_agent_job) { release.job('pcap-agent') }
end

RSpec.configure do |config|
  config.include SharedContext
end