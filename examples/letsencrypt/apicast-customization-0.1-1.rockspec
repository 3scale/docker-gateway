package = "apicast-customization"
source = { url = '.' }
version = '0.1-1'
dependencies = {
  'lua-resty-auto-ssl > 0',
  'lua-resty-repl > 0'
}
build = {
   type = "builtin",
   modules = {}
}
