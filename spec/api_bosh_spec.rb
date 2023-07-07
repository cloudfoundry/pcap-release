# frozen_string_literal: true

require 'rspec'
require 'yaml'

describe 'config/pcap-api.yml bosh properties' do
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

  context 'when pcap-api.bosh is provided without mTLS' do
    let(:bosh_properties) do
      {
        'bosh' =>
          {
            'agent_port' => 9495,
            'director_url' => 'https://bosh.service.cf.internal:8080',
            'token_scope' => 'bosh.admin',
            'tls' =>
            {
              'enabled' => false
            }
          }
      }
    end

    it 'configures bosh correctly' do
      properties.merge!(bosh_properties)
      expect(pcap_api_conf['bosh']['agent_port']).to be(9495)
      expect(pcap_api_conf['bosh']['director_url']).to include('https://bosh.service.cf.internal:8080')
      expect(pcap_api_conf['bosh']['token_scope']).to include('bosh.admin')
      expect(pcap_api_conf['bosh']['tls']).to be_nil
    end
  end

  context 'when pcap-api.bosh is provided with skip server verification' do
    let(:bosh_properties) do
      {
        'bosh' =>
          {
            'director_url' => 'https://bosh.service.cf.internal:8080',
            'token_scope' => 'bosh.admin',
            'tls' => {
              'enabled' => true,
              'common_name' => 'bosh.service.cf.internal',
              'skip_verify' => true
            }
          }
      }
    end

    it 'configures bosh correctly' do
      properties.merge!(bosh_properties)
      expect(pcap_api_conf['bosh']['director_url']).to include('https://bosh.service.cf.internal:8080')
      expect(pcap_api_conf['bosh']['tls']['skip_verify']).to be(true)
      expect(pcap_api_conf['bosh']['tls']['ca']).to include('/var/vcap/jobs/pcap-api/config/certs/bosh/pcap-api-bosh-ca.crt')
    end
  end

  context 'when pcap-api.bosh is provided with TLS configuration' do
    let(:bosh_properties) do
      {
        'bosh' =>
          {
            'director_url' => 'https://bosh.service.cf.internal:8080',
            'token_scope' => 'bosh.admin',
            'tls' => {
              'enabled' => true,
              'common_name' => 'bosh.service.cf.internal',
              'skip_verify' => false
            }
          }
      }
    end

    it 'configures bosh correctly' do
      properties.merge!(bosh_properties)
      expect(pcap_api_conf['bosh']['director_url']).to include('https://bosh.service.cf.internal:8080')
      expect(pcap_api_conf['bosh']['tls']['skip_verify']).to be(false)
      expect(pcap_api_conf['bosh']['tls']['ca']).to include('/var/vcap/jobs/pcap-api/config/certs/bosh/pcap-api-bosh-ca.crt')
    end
  end
end
