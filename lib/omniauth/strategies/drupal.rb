require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Drupal < OmniAuth::Strategies::OAuth2
      attr_accessor :session_id, :session_name

      option :app_options, { app_event_id: nil }

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
          is_member: is_member,
          access: raw_info['access']
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
        slug = request.params['slug']
        @app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')

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
            self.env['omniauth.origin'] = '/' + slug
            self.env['omniauth.app_event_id'] = @app_event.id
            finalize_app_event
            call_app!
          else
            @app_event.fail!
            fail!(:invalid_credentials)
          end
        else
          @app_event.logs.create(level: 'error', text: 'Invalid credentials')
          @app_event.fail!
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

      def app_event_log_response(callee, response)
        response_log = "Drupal Authentication Response ##{callee} (code: #{response&.code}):\n#{response.inspect}"
        log_level = response.success? ? 'info' : 'error'
        @app_event.logs.create(level: log_level, text: response_log)
      end

      def authenticate
        request_log = "Drupal Authentication Request:\nPOST #{authenticate_url}"
        @app_event.logs.create(level: 'info', text: request_log)
        response = Typhoeus.post(authenticate_url, body: {
          username: username,
          password: password}
        )
        app_event_log_response(__callee__, response)
        response
      end

      def authenticate_url
        "#{options.client_options.site}#{options.client_options.authenticate_url}"
      end

      def finalize_app_event
        app_event_data = {
          user_info: {
            uid: uid,
            first_name: info[:first_name],
            last_name: info[:last_name],
            email: info[:email]
          }
        }

        @app_event.update(raw_data: app_event_data)
      end

      def get_user_info(token, member_id)
        request_log = "Drupal Authentication Request:\nPOST #{user_info_url}, token: #{token}"
        @app_event.logs.create(level: 'info', text: request_log)
        response = Typhoeus.post(user_info_url,
          body: { uid: member_id },
          headers: {'Cookie' => "#{session_name}=#{session_id}", 'X-CSRF-Token' => token})
        app_event_log_response(__callee__, response)
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
