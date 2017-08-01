require 'sinatra'
require 'sinatra/activerecord'
require 'active_record'
require './models/user'
require 'oauth2'
require 'json'
require 'dotenv'
require 'sinatra/partial'
require 'jwt'

Dotenv.load
register Sinatra::Partial
enable :partial_underscores
set :partial_template_engine, :erb
enable :sessions

SCOPES = ['https://www.googleapis.com/auth/userinfo.email'].join(' ')

signing_key_path = File.expand_path("../app.rsa", __FILE__)
verify_key_path = File.expand_path("../app.rsa.pub", __FILE__)

signing_key = ""
verify_key = ""

File.open(signing_key_path) do |file|
  signing_key = OpenSSL::PKey.read(file)
end

File.open(verify_key_path) do |file|
  verify_key = OpenSSL::PKey.read(file)
end

set :signing_key, signing_key
set :verify_key, verify_key

def check_g_api_client
  raise 'You must specify the G_API_CLIENT env variable' unless ENV['OAUTH2_CLIENT_ID']
end

def check_g_api_secret
  raise 'You must specify the G_API_SECRET env veriable' unless ENV['OAUTH2_CLIENT_SECRET']
end

check_g_api_client
check_g_api_secret

get '/' do
  @users = User.all
  if session[:access_token]
    @encoded_token = JWT.encode(session[:access_token], settings.signing_key, "RS256")
    @decoded_token = JWT.decode(@encoded_token, settings.verify_key, true)
  end
  erb :index
end

get '/auth' do
  redirect client.auth_code.authorize_url(:redirect_uri => redirect_uri,
                                          :scope => SCOPES,
                                          :access_type => 'offline')
end

get '/oauth2callback' do
  access_token = client.auth_code.get_token(params[:code], :redirect_uri => redirect_uri)
  session[:access_token] = access_token.token
  session[:email] = access_token.get('https://www.googleapis.com/userinfo/email?alt=json').parsed
  redirect '/'
end

get '/logout' do
  session[:access_token] = nil
  redirect '/'
end

post '/create' do
  User.create(first_name: params[:username])
  redirect '/'
end

post '/delete' do
  begin
  User.last.delete
  rescue Exception => e
    puts e.message
    puts e.backtrace.inspect
  end
  redirect '/'
end

private
def redirect_uri
  uri = URI.parse(request.url)
  uri.path = '/oauth2callback'
  uri.query = nil
  uri.to_s
end

def client
  client ||= OAuth2::Client.new(ENV['OAUTH2_CLIENT_ID'], ENV['OAUTH2_CLIENT_SECRET'], {
    :site => 'https://accounts.google.com',
    :authorize_url => "/o/oauth2/auth",
    :token_url => "/o/oauth2/token"
  })
end
