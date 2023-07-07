# frozen_string_literal: true

require 'rspec'
require 'yaml'

describe 'config/pcap-api.yml global properties' do
  let(:template) { pcap_api_job.template('config/pcap-api.yml') }

  let(:pcap_api_conf) { YAML.safe_load(template.render({ 'pcap-api' => properties }, spec: pcap_api_spec)) }

  let(:properties) do
    {
      'concurrent_captures' => 10,
      'buffer' => {
        'size' => 100,
        'upper_limit' => 98,
        'lower_limit' => 90
      }
    }
  end

  context 'when pcap-api.id is set automatically' do
    it 'configures correctly' do
      expect(pcap_api_conf['id']).to include('pcap-api/f9281cda-1234-bbcd-ef12-1337cafe0048')
    end
  end

  context 'when pcap-api.log_level is not provided' do
    it 'configures logging correctly' do
      expect(pcap_api_conf['log_level']).to eq('info')
    end
  end

  context 'when pcap-api.log_level is provided' do
    let(:log_level) do
      {
        'log_level' => 'debug'
      }
    end

    it 'configures logging correctly' do
      properties.merge!(log_level)
      expect(pcap_api_conf['log_level']).to eq('debug')
    end
  end

  context 'when pcap-api.concurrent_captures is provided' do
    let(:concurrent_captures) do
      {
        'concurrent_captures' => 10
      }
    end

    it 'configures value correctly' do
      properties.merge!(concurrent_captures)
      expect(pcap_api_conf['concurrent_captures']).to eq(10)
    end
  end

  context 'when pcap-api.listen port is not provided' do
    it 'configures values correctly' do
      expect(pcap_api_conf['listen']['port']).to eq(8080)
    end
  end

  context 'when pcap-api.listen port provided' do
    let(:listen) do
      {
        'listen' => {
          'port' => 8082
        }
      }
    end

    it 'configures values correctly' do
      properties.merge!(listen)
      expect(pcap_api_conf['listen']['port']).to eq(8082)
    end
  end

  context 'when platform-TLS is disabled' do
    let(:listen) do
      {
        'listen' => {
          'tls' => {
            'enabled' => 'false'
          }
        }
      }
    end

    it 'does not configure certificates for pcap-api' do
      properties.merge!(listen)
      expect(pcap_api_conf['listen']).not_to have_key('tls')
    end
  end

  context 'when pcap-api.tls config provided' do
    let(:listen) do
      {
        'listen' => {
          'tls' => {
            'certificate' => 'test',
            'private_key' => 'test',
            'ca' => 'test'
          }
        }
      }
    end

    it 'configures pcap-api TLS settings correctly' do
      properties.merge!(listen)
      expect(pcap_api_conf['listen']['tls']['certificate']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api.crt')
      expect(pcap_api_conf['listen']['tls']['private_key']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api.key')
      expect(pcap_api_conf['listen']['tls']['client_cas']).to include('/var/vcap/jobs/pcap-api/config/certs/pcap-api-ca.crt')
    end
  end

  context 'when pcap-api.buffer provided' do
    let(:buffer) do
      {
        'buffer' => {
          'size' => 500,
          'upper_limit' => 498,
          'lower_limit' => 450
        }
      }
    end

    it 'configures values correctly' do
      properties.merge!(buffer)
      expect(pcap_api_conf['buffer']['size']).to eq(500)
      expect(pcap_api_conf['buffer']['upper_limit']).to eq(498)
      expect(pcap_api_conf['buffer']['lower_limit']).to eq(450)
    end
  end
end
