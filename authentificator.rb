require 'dotenv'

class Authentificator
  SCOPES        = ['https://www.googleapis.com/auth/userinfo.email'].join(' ')
  SITE          = 'https://accounts.google.com'.freeze
  AUTHORIZE_URL = '/o/oauth2/auth'.freeze
  TOKEN_URL     = '/o/oauth2/token'.freeze
  APP_BASE_URL  = 'http://localhost:4567'.freeze

  def initialize
    raise 'You must specify the G_API_CLIENT env variable' unless ENV['OAUTH2_CLIENT_ID']
    raise 'You must specify the G_API_SECRET env veriable' unless ENV['OAUTH2_CLIENT_SECRET']
  end

  def authorize_url
    client.auth_code.authorize_url(redirect_uri: redirect_uri, scope: SCOPES, access_type: 'offline')
  end

  def fetch_access_token(code)
    client.auth_code.get_token(code, redirect_uri: redirect_uri)
  end

  private

  def redirect_uri
    URI("#{APP_BASE_URL}/oauth2callback")
  end

  def client
    OAuth2::Client.new(ENV['OAUTH2_CLIENT_ID'], ENV['OAUTH2_CLIENT_SECRET'], site: SITE,
                                                                             authorize_url: AUTHORIZE_URL,
                                                                             token_url: TOKEN_URL)
  end
end
