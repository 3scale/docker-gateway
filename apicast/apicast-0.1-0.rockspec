package = "apicast"
source = { url = '.' }
version = '0.1-0'
dependencies = {
  'lua-resty-http == 0.09-0',
  'inspect == 3.1.0-1',
  'router == 2.1-0',
  'resty-newrelic == 0.01-6'

}
build = {
   type = "builtin",
   modules = {
   }
}
