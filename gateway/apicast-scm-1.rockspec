package = "apicast"
version = "scm-1"
source = {
   url = "git+https://github.com/3scale/apicast.git",
   branch = 'master'
}
description = {
   detailed = "3scale API Gateway",
   homepage = "https://github.com/3scale/apicast",
   license = "Apache License 2.0"
}
dependencies = {
   'lua-resty-http',
   'inspect',
   'lyaml',
   'router',
   'lua-resty-jwt',
   'lua-resty-url',
   'lua-resty-env',
   'lua-resty-execvp',
   'liquid',
   'argparse',
   'penlight',
   'nginx-lua-prometheus',
   'lua-resty-jit-uuid',
}
build = {
   type = "make",
   makefile = 'gateway/Makefile',
   build_pass = false,
   build_variables = {
      CFLAGS='$(CFLAGS)'
   },
   install_variables = {
      INST_PREFIX="$(PREFIX)",
      INST_BINDIR="$(BINDIR)",
      INST_LIBDIR="$(LIBDIR)",
      INST_LUADIR="$(LUADIR)",
      INST_CONFDIR="$(CONFDIR)",
   },
}
