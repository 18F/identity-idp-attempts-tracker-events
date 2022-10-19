# frozen_string_literal: true

require 'json'
require 'aws-sdk-secretsmanager'
require 'yaml'

module LoginGov
  module IdpAttemptsTracker
    # Class holding configuration for this sample app. Defaults come from
    # `#default_config`, with keys overridden by data from
    # `config/application.yml` if it exists.
    class Config
      # @param [String] config_file Location of application.yml
      def initialize(config_file: nil)
        @config = default_config

        config_file ||= File.dirname(__FILE__) + '/config/application.yml'
        if File.exist?(config_file)
          @config.merge!(YAML.safe_load(File.read(config_file)))
        end
      end

      def idp_url
        @config.fetch('idp_url')
      end

      def attempts_api_auth_tokens
        @config.fetch('attempts_api_auth_tokens')
      end

      def attempts_api_path
        @config.fetch('attempts_api_path')
      end

      # @return [OpenSSL::PKey::RSA]
      def attempts_private_key
        @attempts_private_key ||= OpenSSL::PKey::RSA.new(get_sp_private_key_raw(@config.fetch('irs_private_key_path')))
      end

      def attempts_api_csp_id
        @config.fetch('attempts_api_csp_id')
      end

      def basic_username
        @config.fetch('basic_username')
      end

      def basic_password
        @config.fetch('basic_password')
      end

      # Define the default configuration values. If application.yml exists, those
      # values will be merged in overriding defaults.
      #
      # @return [Hash]
      #
      def default_config
        data = {
          'irs_private_key_path' => ENV['irs_private_key_path'] || './config/demo_irs_pk.key',
          'attempts_api_path' => ENV['attempts_api_path'] || '/api/irs_attempts_api/security_events',
          'attempts_api_auth_tokens' => ENV['attempts_api_auth_tokens'] || 'test-token-1,test-token-2',
          'attempts_api_csp_id' => ENV['attempts_api_csp_id'] || 'Login.gov',
          'basic_username' => ENV['basic_username'] || 'admin',
          'basic_password' => ENV['basic_password'] || 'admin',
        }

        # EC2 deployment defaults

        env = ENV['idp_environment'] || 'dev'
        domain = ENV['idp_domain'] || 'identitysandbox.gov'

        data['idp_url'] = ENV['idp_url']
        unless data['idp_url']
          if env == 'prod'
            data['idp_url'] = "https://secure.#{domain}"
          else
            data['idp_url'] = "https://idp.#{env}.#{domain}"
          end
        end

        data
      end

      private

      def get_sp_private_key_raw(path)
        if path.start_with?('aws-secretsmanager:')
          secret_id = path.split(':', 2).fetch(1)
          opts = {}
          smc = Aws::SecretsManager::Client.new(opts)
          begin
            return smc.get_secret_value(secret_id: secret_id).secret_string
          rescue Aws::SecretsManager::Errors::ResourceNotFoundException
            if ENV['deployed']
              raise
            end
          end

          STDERR.puts "#{secret_id.inspect}: not found in AWS Secrets Manager, using demo key"
          get_sp_private_key_raw(demo_private_key_path)
        else
          File.read(path)
        end
      end

      def demo_private_key_path
        File.dirname(__FILE__) + '/config/demo_irs_pk.key'
      end
    end
  end
end
