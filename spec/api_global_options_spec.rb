# frozen_string_literal: true
require 'rspec'
require 'yaml'

describe "config/pcap-api.yml global properties" do
  let(:template) { pcap_api_job.template('config/pcap-api.yml') }

  let(:pcap_api_conf) { YAML.safe_load(template.render({ 'pcap-api' => properties })) }

  let(:log_level) { pcap_api_conf['log_level'] }

  context 'when pcap-api.log_level is not provided' do
      let(:properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048'
      }
      end
      it 'configures logging correctly' do
        expect(log_level).to eq("info")
      end
  end

  context 'when pcap-api.log_level is provided' do
      let(:properties) do
        {
          'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
          'log_level' => 'debug'
        }
      end
      it 'configures logging correctly' do
        expect(log_level).to eq('debug')
      end
  end

  context 'when pcap-api.concurrent_captures is not provided' do
      let(:properties) do
        {
          'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048'
        }
        end
        it 'configures value correctly' do
          expect(pcap_api_conf['concurrent_captures']).to eq(5)
        end
  end

  context 'when pcap-api.concurrent_captures is provided' do
      let(:properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'concurrent_captures' => 10
      }
      end
      it 'configures value correctly' do
        expect(pcap_api_conf['concurrent_captures']).to eq(10)
      end
  end

  context 'when pcap-api.listen port is not provided' do
    let(:properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
      }
    end
    it 'configures values correctly' do
      expect(pcap_api_conf['listen']['port']).to eq(8080)
    end
  end

  context 'when pcap-api.listen port provided' do
    let(:properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'listen' => {
          'port' => 8082
        }
      }
    end
    it 'configures values correctly' do
      expect(pcap_api_conf['listen']['port']).to eq(8082)
    end
  end

  context 'when pcap-api.buffer is not provided' do
      let(:properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048'
      }
      end
      it 'configures values correctly' do
        expect(pcap_api_conf['buffer']['size']).to eq(100)
        expect(pcap_api_conf['buffer']['upper_limit']).to eq(98)
        expect(pcap_api_conf['buffer']['lower_limit']).to eq(70)
      end
  end

  context 'when pcap-api.buffer provided' do
      let(:properties) do
      {
        'id' => 'f9281cda-1234-bbcd-ef12-1337cafe0048',
        'buffer' => {
          'size' => 1000,
          'upper_limit' => 998,
          'lower_limit' => 900,
        },
      }
      end
      it 'configures values correctly' do
        expect(pcap_api_conf['buffer']['size']).to eq(1000)
        expect(pcap_api_conf['buffer']['upper_limit']).to eq(998)
        expect(pcap_api_conf['buffer']['lower_limit']).to eq(900)
      end
  end
end