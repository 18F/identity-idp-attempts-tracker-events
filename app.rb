# frozen_string_literal: true

require 'dotenv/load'
require 'active_support/core_ext/hash/indifferent_access'
require 'active_support/all'
require 'erubi'
require 'faraday'
require 'json'
require 'json/jwt'
require 'jwt'
require 'jwe'
require 'openssl'
require 'securerandom'
require 'sinatra/base'
require 'time'
require 'logger'

require_relative './config'
require_relative './lib/base16'

module LoginGov::IdpAttemptsTracker
  class AppError < StandardError; end

  class Events < Sinatra::Base
    set :erb, escape_html: true
    set :logger, Logger.new(STDOUT)

    enable :sessions

    configure :development do
      require 'byebug'
    end

    def config
      @config ||= Config.new
    end

    helpers do
      def protected!
        return if authorized?
        response['WWW-Authenticate'] = %(Basic realm="Restricted Area")
        throw(:halt, [401, "Not authorized\n"])
      end

      def authorized?
        @auth ||= Rack::Auth::Basic::Request.new(request.env)
        @auth.provided? and @auth.basic? and @auth.credentials and @auth.credentials == [config.basic_username, config.basic_password]
      end
    end

    get '/' do
      protected!
      decrypted_events = []
      irs_attempt_api_auth_token = config.attempts_api_auth_tokens.split(',').last

      conn = Faraday.new(
        url: config.idp_url,
        headers: { 'Authorization' => "Bearer #{config.attempts_api_csp_id} #{irs_attempt_api_auth_token}" }
      )
      body = "timestamp=#{ActiveSupport::TimeZone['UTC'].now.iso8601}"
      resp = conn.post(config.attempts_api_path, body)

      if resp.status == 200
        iv = Base64.strict_decode64(resp.headers['x-payload-iv'])
        encrypted_key = Base64.strict_decode64(resp.headers['x-payload-key'])
        begin
          private_key = config.attempts_private_key
          key = private_key.private_decrypt(encrypted_key)
          decrypted = decrypt_attempts_response(
            encrypted_data: resp.body, key: key, iv: iv,
          )

          events = decrypted.split("\r\n")
          events && events.each do |jwe|
            begin
              decrypted_events << JSON.parse(JWE.decrypt(jwe, private_key))
            rescue
              puts 'Failed to parse/decrypt event!'
            end
          end
        rescue StandardError => err
          response_status = 422
          response_error = err.inspect
        end
      else
        response_status = resp.status
        response_error = resp.body
      end

      erb :index, locals: {
        events: decrypted_events&.sort_by { |e| -e["iat"] },
        response_status: response_status,
        response_error: response_error,
      }
    end

    private

    def decrypt_attempts_response(encrypted_data:, key:, iv:)
      cipher = OpenSSL::Cipher.new('aes-256-cbc')
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv
      decrypted = cipher.update(Base16.decode16(encrypted_data)) + cipher.final

      Zlib.gunzip(decrypted)
    end

    def json(response)
      JSON.parse(response.to_s).with_indifferent_access
    end
  end
end
