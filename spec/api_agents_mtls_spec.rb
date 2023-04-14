# frozen_string_literal: true
require 'rspec'
require 'yaml'

describe "config/pcap-api.yml agents properties" do
  let(:template) { pcap_api_job.template('config/pcap-api.yml') }

  let(:pcap_api_conf) { YAML.safe_load(template.render({ 'pcap-api' => properties })) }

  context 'when pcap-api.agents_mtls is provided without mTLS' do
    let(:properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'agents_mtls' => {
          'enabled' => 'false'
        }
      }
    end
    it 'configures correctly' do
    end
  end

  context 'when pcap-api.agents_mtls is provided with skip server verification' do
    let(:properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'agents_mtls' => {
              'enabled' => true,
              'common_name' => 'pcap-agent-test.service.cf.internal',
              'skip_verify' => true
        }
      }
    end
    it 'configures correctly' do
      expect(pcap_api_conf['agents_mtls']['skip_verify']).to be(true)
      expect(pcap_api_conf['agents_mtls']['common_name']).to include('pcap-agent-test.service.cf.internal')
      expect(pcap_api_conf['agents_mtls']['tls']['certificate']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-client.crt')
      expect(pcap_api_conf['agents_mtls']['tls']['private_key']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-client.key')
      expect(pcap_api_conf['agents_mtls']['tls']['ca']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-client.ca')

    end
  end

  context 'when pcap-api.agents_mtls is enabled with mTLS configuration' do
    let(:properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'agents_mtls' => {
          'enabled' => true,
        }
      }
    end
    it 'takes defaults correctly' do
      expect(pcap_api_conf['agents_mtls']['skip_verify']).to be(false)
      expect(pcap_api_conf['agents_mtls']['common_name']).to include('pcap-agent.service.cf.internal')
      expect(pcap_api_conf['agents_mtls']['tls']['certificate']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-client.crt')
      expect(pcap_api_conf['agents_mtls']['tls']['private_key']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-client.key')
      expect(pcap_api_conf['agents_mtls']['tls']['ca']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-client.ca')

    end
  end

end