# frozen_string_literal: true

require 'bosh/template/test'

module SharedContext
  extend RSpec::SharedContext

  let(:release_path) { File.join(File.dirname(__FILE__), '..') }
  let(:release) { Bosh::Template::Test::ReleaseDir.new(release_path) }
  let(:pcap_api_job) { release.job('pcap-api') }
  let(:pcap_agent_job) { release.job('pcap-agent') }
  let(:pcap_api_spec) do
    {
      'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
      'name' => "pcap-api"
    }
  end
end

RSpec.configure do |config|
  config.include SharedContext
end