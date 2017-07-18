require 'sinatra'
require 'sinatra/activerecord'
require 'active_record'
require './models/user'
require 'oauth2'
require 'json'
require 'dotenv'
require 'sinatra/partial'
Dotenv.load
register Sinatra::Partial
enable :partial_underscores
set :partial_template_engine, :erb
enable :sessions

SCOPES = ['https://www.googleapis.com/auth/userinfo.email'].join(' ')

unless G_API_CLIENT = ENV['OAUTH2_CLIENT_ID']
  raise "You must specify the G_API_CLIENT env variable"
end

unless G_API_SECRET = ENV['OAUTH2_CLIENT_SECRET']
  raise "You must specify the G_API_SECRET env veriable"
end

get '/' do
  @users = User.all
  erb :index
end

get "/auth" do
  redirect client.auth_code.authorize_url(:redirect_uri => redirect_uri,:scope => SCOPES,:access_type => "offline")
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
  client ||= OAuth2::Client.new(G_API_CLIENT, G_API_SECRET, {
                :site => 'https://accounts.google.com',
                :authorize_url => "/o/oauth2/auth",
                :token_url => "/o/oauth2/token"
              })
end
