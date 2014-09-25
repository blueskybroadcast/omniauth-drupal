require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Drupal < OmniAuth::Strategies::OAuth2
      attr_accessor :session_id, :session_name

      option :client_options, {
        site: 'http://ncs-civicrm.prometdev.com',
        authorize_url: '/user',
        authenticate_url: '/api/remote_login/user/login',
        user_info_url: '/api/remote_login/sso/retriever',
        username: 'MUST BE SET',
        password: 'MUST BE SET'
      }

      uid { member_id }

      name {'drupal'}

      info do
        {
          first_name: raw_info['first_name'],
          last_name: raw_info['last_name'],
          email: raw_info['email'],
          is_member: is_member
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      def creds
        self.access_token
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        redirect client.auth_code.authorize_url({:return_url => callback_url + "?slug=#{slug}"})
      end

      def callback_phase
        if member_id
          response = authenticate

          if response.success?
            response_body = JSON.parse(response.body)
            self.access_token = {
              :token => response_body['token']
            }

            self.session_id = response_body['sessid']
            self.session_name = response_body['session_name']

            self.env['omniauth.auth'] = auth_hash
            self.env['omniauth.origin'] = '/' + request.params['slug']
            call_app!
          else
            fail!(:invalid_credentials)
          end
        else
          fail!(:invalid_credentials)
        end
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash.credentials = creds
        hash
      end

      def raw_info
        @raw_info ||= get_user_info(access_token[:token], member_id)
      end

      private

      def authenticate
        Typhoeus.post(authenticate_url, body: {
          username: username,
          password: password}
        )
      end

      def authenticate_url
        "#{options.client_options.site}#{options.client_options.authenticate_url}"
      end

      def get_user_info(token, member_id)
        response = Typhoeus.post(user_info_url,
          body: { uid: member_id },
          headers: {'Cookie' => "#{session_name}=#{session_id}", 'X-CSRF-Token' => token})

        if response.success?
          JSON.parse(response.body)
        else
          nil
        end
      end

      def is_member
        raw_info['acct_status'] == '1'
      end

      def member_id
        request.params['memberID']
      end

      def password
        options.client_options.password
      end

      def username
        options.client_options.username
      end

      def user_info_url
        "#{options.client_options.site}#{options.client_options.user_info_url}"
      end
    end
  end
end
