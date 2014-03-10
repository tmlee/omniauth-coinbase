require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Coinbase < OmniAuth::Strategies::OAuth2
      option :name, 'coinbase'
      option :client_options, {
              :site => 'https://coinbase.com',
              :proxy => ENV['http_proxy'] ? URI(ENV['http_proxy']) : nil
      }

      uid { raw_info['id'] }

      info do
        {
          :id => raw_info['id'],
          :name => raw_info['name'],
          :email => raw_info['email'],
          :balance => raw_info['balance']['amount']
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      def authorize_params
        super.tap do |params|
          %w[scope meta[name] meta[send_limit_amount] meta[send_limit_currency] meta[send_limit_period]].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end

      def raw_info
        @raw_info ||= MultiJson.load(access_token.get('/api/v1/users').body)['users'][0]['user']
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

    end
  end
end
