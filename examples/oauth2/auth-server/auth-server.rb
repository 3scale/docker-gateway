require 'sinatra'

set :bind, '0.0.0.0'
nginx_redirect_uri =  "http://localhost:8080/callback?"  #nginx callback
enable :sessions
set :session_secret, '*&(^B234'

get("/") do
  erb :root
end

get("/auth/login") do
  session[:client_id]=params[:client_id]
  session[:redirect_uri]=params[:redirect_uri]
  session[:scope]=params[:scope]
  session[:state] = params[:state]
  session[:pre_token] = params[:tok]
  erb :login
end

post("/auth/login") do
  redirect "/consent"
end

get("/consent") do
  @client_id = session[:client_id]
  @scope = session[:scope]
  erb :consent
end

get("/authorized") do  
  callback =  "#{nginx_redirect_uri}state=#{session[:state]}&redirect_uri=#{session[:redirect_uri]}"
  puts callback
  redirect callback
end

get("/denied") do 
  callback =  "#{session[:redirect_uri]}#error=access_deniedt&error_description=resource_owner_denied_request&state=#{session[:state]}"
  puts callback
  redirect callback
end