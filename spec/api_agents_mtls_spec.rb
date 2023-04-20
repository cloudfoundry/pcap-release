# frozen_string_literal: true

require 'rspec'
require 'yaml'

describe 'config/pcap-api.yml agents properties' do
  let(:template) { pcap_api_job.template('config/pcap-api.yml') }

  let(:pcap_api_conf) { YAML.safe_load(template.render({ 'pcap-api' => properties }, spec: pcap_api_spec)) }

  let(:properties) do
    {
      'concurrent_captures' => 5,
      'buffer' => {
        'size' => 100,
        'upper_limit' => 98,
        'lower_limit' => 90
      }
    }
  end

  context 'when pcap-api.agents_mtls is disabled' do
    let(:agents_mtls_properties) do
      {
        'agents_mtls' => {
          'enabled' => 'false'
        }
      }
    end

    it 'configures correctly' do
      properties.merge!(agents_mtls_properties)
      expect(pcap_api_conf['agents_mtls']).to be_nil
    end
  end

  context 'when pcap-api.agents_mtls is provided with skip server verification' do
    let(:agents_mtls_properties) do
      {
        'agents_mtls' => {
          'enabled' => true,
          'common_name' => 'pcap-agent-test.service.cf.internal',
          'skip_verify' => true
        }
      }
    end

    it 'configures correctly' do
      properties.merge!(agents_mtls_properties)
      expect(pcap_api_conf['agents_mtls']['skip_verify']).to be(true)
      expect(pcap_api_conf['agents_mtls']['common_name']).to include('pcap-agent-test.service.cf.internal')
      expect(pcap_api_conf['agents_mtls']['certificate']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-client.crt')
      expect(pcap_api_conf['agents_mtls']['private_key']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-client.key')
      expect(pcap_api_conf['agents_mtls']['ca']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-client-ca.crt')
    end
  end

  context 'when pcap-api.agents_mtls is enabled with mTLS configuration' do
    let(:agents_mtls_properties) do
      {
        'agents_mtls' => {
          'enabled' => true
        }
      }
    end

    it 'takes defaults correctly' do
      properties.merge!(agents_mtls_properties)
      expect(pcap_api_conf['agents_mtls']['skip_verify']).to be(false)
      expect(pcap_api_conf['agents_mtls']['common_name']).to include('pcap-agent.service.cf.internal')
      expect(pcap_api_conf['agents_mtls']['certificate']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-client.crt')
      expect(pcap_api_conf['agents_mtls']['private_key']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-client.key')
      expect(pcap_api_conf['agents_mtls']['ca']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-client-ca.crt')
    end
  end
end
