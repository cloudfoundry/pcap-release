# frozen_string_literal: true

require 'rspec'

require 'yaml'

describe 'config/pcap-agent.yml global properties' do
  let(:agent_template) { pcap_agent_job.template('config/pcap-agent.yml') }

  let(:pcap_agent_conf) { YAML.safe_load(agent_template.render({ 'pcap-agent' => agent_properties })) }

  context 'when pcap-agent.log_level is not provided' do
    let(:agent_properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'buffer' => {
          'size' => 100,
          'upper_limit' => 98,
          'lower_limit' => 90
        }
      }
    end

    it 'configures logging correctly' do
      expect(pcap_agent_conf['log_level']).to eq('info')
    end
  end

  context 'when pcap-agent.log_level is provided' do
    let(:agent_properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'log_level' => 'debug',
        'buffer' => {
          'size' => 100,
          'upper_limit' => 98,
          'lower_limit' => 90
        }
      }
    end

    it 'configures logging correctly' do
      expect(pcap_agent_conf['log_level']).to eq('debug')
    end
  end

  context 'when pcap_agent.buffer provided' do
    let(:agent_properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'buffer' => {
          'size' => 100,
          'upper_limit' => 98,
          'lower_limit' => 90
        }
      }
    end

    it 'configures values correctly' do
      expect(pcap_agent_conf['buffer']['size']).to eq(100)
      expect(pcap_agent_conf['buffer']['upper_limit']).to eq(98)
      expect(pcap_agent_conf['buffer']['lower_limit']).to eq(90)
    end
  end

  context 'when pcap_agent.listen is no provided' do
    let(:agent_properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'buffer' => {
          'size' => 1000,
          'upper_limit' => 998,
          'lower_limit' => 900
        }
      }
    end

    it 'configures values correctly' do
      expect(pcap_agent_conf['listen']['port']).to be(9494)
      expect(pcap_agent_conf['listen']['tls']['certificate']).to include('/var/vcap/jobs/pcap-agent/config/certs/pcap-agent.crt')
      expect(pcap_agent_conf['listen']['tls']['private_key']).to include('/var/vcap/jobs/pcap-agent/config/certs/pcap-agent.key')
      expect(pcap_agent_conf['listen']['tls']['ca']).to include('/var/vcap/jobs/pcap-agent/config/certs/client-ca.crt')
    end
  end

  context 'when pcap_agent.listen.port is provided' do
    let(:agent_properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'buffer' => {
          'size' => 1000,
          'upper_limit' => 998,
          'lower_limit' => 900
        },
        'listen' => {
          'port' => 9495
        }
      }
    end

    it 'configures values correctly' do
      expect(pcap_agent_conf['listen']['port']).to be(9495)
    end
  end
end
