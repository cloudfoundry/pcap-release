# frozen_string_literal: true

require 'rspec'
require 'yaml'

describe 'config/pcap-api.yml bosh properties' do
  let(:template) { pcap_api_job.template('config/pcap-api.yml') }

  let(:pcap_api_conf) { YAML.safe_load(template.render({ 'pcap-api' => properties }, spec: pcap_api_spec)) }

  context 'when pcap-api.bosh is provided without mTLS' do
    let(:properties) do
      {
        'bosh' =>
          {
            'agent_port' => 9495,
            'director_url' => 'https://bosh.service.cf.internal:8080',
            'token_scope' => 'bosh.admin',
            'mtls' =>
            {
              'enabled' => false
            }
          }
      }
    end

    it 'configures bosh correctly' do
      expect(pcap_api_conf['bosh']['agent_port']).to be(9495)
      expect(pcap_api_conf['bosh']['director_url']).to include('https://bosh.service.cf.internal:8080')
      expect(pcap_api_conf['bosh']['token_scope']).to include('bosh.admin')
      expect(pcap_api_conf['bosh']['mtls']).to be_nil
    end
  end

  context 'when pcap-api.bosh is provided with skip server verification' do
    let(:properties) do
      {
        'bosh' =>
          {
            'director_url' => 'https://bosh.service.cf.internal:8080',
            'token_scope' => 'bosh.admin',
            'mtls' => {
              'enabled' => true,
              'common_name' => 'bosh.service.cf.internal',
              'skip_verify' => true
            }
          }
      }
    end

    it 'configures bosh correctly' do
      expect(pcap_api_conf['bosh']['director_url']).to include('https://bosh.service.cf.internal:8080')
      expect(pcap_api_conf['bosh']['mtls']['skip_verify']).to be(true)
      expect(pcap_api_conf['bosh']['mtls']['tls']['certificate']).to include('/var/vcap/jobs/pcap-api/config/certs/bosh/pcap-api-bosh.crt')
      expect(pcap_api_conf['bosh']['mtls']['tls']['private_key']).to include('/var/vcap/jobs/pcap-api/config/certs/bosh/pcap-api-bosh.key')
      expect(pcap_api_conf['bosh']['mtls']['tls']['ca']).to include('/var/vcap/jobs/pcap-api/config/certs/bosh/pcap-api-bosh-ca.crt')
    end
  end

  context 'when pcap-api.bosh is provided with TLS configuration' do
    let(:properties) do
      {
        'bosh' =>
          {
            'director_url' => 'https://bosh.service.cf.internal:8080',
            'token_scope' => 'bosh.admin',
            'mtls' => {
              'enabled' => true,
              'common_name' => 'bosh.service.cf.internal',
              'skip_verify' => false
            }
          }
      }
    end

    it 'configures bosh correctly' do
      expect(pcap_api_conf['bosh']['director_url']).to include('https://bosh.service.cf.internal:8080')
      expect(pcap_api_conf['bosh']['mtls']['skip_verify']).to be(false)
      expect(pcap_api_conf['bosh']['mtls']['tls']['certificate']).to include('/var/vcap/jobs/pcap-api/config/certs/bosh/pcap-api-bosh.crt')
      expect(pcap_api_conf['bosh']['mtls']['tls']['private_key']).to include('/var/vcap/jobs/pcap-api/config/certs/bosh/pcap-api-bosh.key')
      expect(pcap_api_conf['bosh']['mtls']['tls']['ca']).to include('/var/vcap/jobs/pcap-api/config/certs/bosh/pcap-api-bosh-ca.crt')
    end
  end
end
