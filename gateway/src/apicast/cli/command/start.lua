local setmetatable = setmetatable
local pairs = pairs
local min = math.min
local max = math.max
local insert = table.insert
local concat = table.concat
local format = string.format
local tostring = tostring
local tonumber = tonumber
local sub = string.sub

local exec = require('resty.execvp')
local resty_env = require('resty.env')
local re = require('ngx.re')
local resty_url = require('resty.url')

local Template = require('apicast.cli.template')
local Environment = require('apicast.cli.environment')

local pl = require'pl.import_into'()

local _M = {
    openresty = { 'openresty-debug', 'openresty', 'nginx' },
    log_levels = { 'emerg', 'alert', 'crit', 'error', 'warn', 'notice', 'info', 'debug' },
    log_level = 5, -- warn
    log_file = 'stderr',
}

local mt = { __index = _M }

local function find_openresty_command(candidates)
    for i=1, #candidates do
        local ok = os.execute(('%s -V 2>/dev/null'):format(candidates[i]))

        if ok then
            return candidates[i]
        end
    end

    error("could not find openresty executable")
end

local function update_env(env)
    for name, value in pairs(env) do
        resty_env.set(name, tostring(value))
    end
end


local function apicast_root()
    return resty_env.value('APICAST_DIR') or pl.path.abspath('.')
end

local function nginx_config(context,path)
    local template = Template:new(context, apicast_root(), true)
    local tmp = pl.path.tmpname()
    pl.file.write(tmp, template:render(path))
    return tmp
end

local function create_prefix()
    local tmp = os.tmpname()

    assert(pl.file.delete(tmp))
    assert(pl.dir.makepath(tmp .. '/logs'))

    return tmp
end

local function get_log_level(self, options)
    local log_level = options.log_level
    local n = #(self.log_levels)
    for i=1, n do
        if self.log_levels[i] == log_level then
            i = i + options.verbose - options.quiet
            log_level = self.log_levels[max(min(i, n), 1)]
            break
        end
    end
    return log_level
end


local function build_environment_config(options)
    local config = Environment.new(options)

    resty_env.set('APICAST_POLICY_LOAD_PATH', concat(options.policy_load_path,':'))

    for i=1, #options.environment do
        local ok, err = config:add(options.environment[i])

        if not ok then
            print('not loading ', options.environment[i], ': ', err)
        end
    end

    if options.dev then config:add('development') end

    config:save()

    return config
end

local function openresty_binary(candidates)
    return resty_env.value('APICAST_OPENRESTY_BINARY') or
        resty_env.value('TEST_NGINX_BINARY') or
        find_openresty_command(candidates)
end

local function to_uri(uri)
    local url = resty_url.parse(uri)

    if url then
        return uri
    elseif uri then
        return format('file:%s', uri)
    end
end

local function build_env(options, config, context)
    return {
        APICAST_CONFIGURATION = to_uri(options.configuration or context.configuration),
        APICAST_CONFIGURATION_LOADER = options.configuration_loader or context.configuration_loader or 'lazy',
        APICAST_CONFIGURATION_CACHE = options.cache or context.configuration_cache,
        THREESCALE_DEPLOYMENT_ENV = context.configuration_channel or options.channel or config.name,
        APICAST_POLICY_LOAD_PATH = concat(options.policy_load_path or context.policy_load_path, ':'),
    }
end

local function build_context(options, config)
    local context = config:context()

    context.worker_processes = options.workers or context.worker_processes

    if options.pid then
        context.pid = pl.path.abspath(options.pid)
    end

    if options.daemon then
        context.daemon = 'on'
    end

    if options.master and options.master[1] == 'off' then
        context.master_process = 'off'
    end


    context.prefix = apicast_root()
    context.ca_bundle = pl.path.abspath(tostring(context.ca_bundle) or pl.path.join(context.prefix, 'conf', 'ca-bundle.crt'))

    context.access_log_file = options.access_log_file

    -- expose parsed CLI options
    context.options = options

    return context
end

function mt:__call(options)
    local openresty = openresty_binary(self.openresty)
    local config = build_environment_config(options)
    local context = build_context(options, config)
    local env = build_env(options, config, context)

    local template_path = options.template

    update_env(env)
    -- also use env from the config file
    update_env(context.env or {})
    local nginx = nginx_config(context, template_path)

    local log_level = get_log_level(self, options)
    local log_file = options.log_file or self.log_file
    local global = {
        ('error_log %s %s'):format(log_file, log_level)
    }
    local prefix = create_prefix()

    local cmd = { '-c', nginx, '-g', concat(global, '; ') .. ';', '-p', prefix }

    if options.test then
        insert(cmd, options.debug and '-T' or '-t')
    end

    if options.signal then
        insert(cmd, '-s')
        insert(cmd,  options.signal)
    end

    return exec(openresty, cmd, env)
end

local function split_by(pattern)
  return function(str)
    return re.split(str or '', pattern, 'oj')
  end
end

local load_env = split_by(':')

local function has_prefix(str, prefix)
    return sub(str, 1, #prefix) == prefix
end

local function abspath(path)
    if not path then return nil end
    if has_prefix(path, 'syslog:') then return path end
    if has_prefix(path, 'memory:') then return path end

    return pl.path.abspath(path)
end

local function configure(cmd)
    cmd:option("--template", "Nginx config template.", 'conf/nginx.conf.liquid')

    local channel = resty_env.value('THREESCALE_DEPLOYMENT_ENV') or 'production'
    local loaded_env = Environment.loaded()

    insert(loaded_env, 1, channel)

    cmd:option('-3 --channel', "3scale configuration channel to use.", channel):action(function(args, name, chan)
      args.environment[1] = chan
      args[name] = chan
    end):count('0-1')
    cmd:option('-e --environment', "Deployment to start. Can also be a path to a Lua file.", resty_env.value('APICAST_ENVIRONMENT'))
      :count('*'):init(loaded_env):action('concat'):convert(load_env)
    cmd:flag('--development --dev', 'Start in development environment'):action(function(arg, name)
      insert(arg.environment, name)
    end)

    cmd:flag("-m --master", "Control nginx master process.", 'on'):args('?')
    cmd:flag("-t --test", "Test the nginx config")
    cmd:flag("--debug", "Debug mode. Prints more information.")
    cmd:option("-c --configuration",
        "Path to custom config file (JSON)",
        resty_env.value('APICAST_CONFIGURATION'))
    cmd:flag("-d --daemon", "Daemonize.")
    cmd:option("-w --workers",
        "Number of worker processes to start.",
        resty_env.value('APICAST_WORKERS') or Environment.default_config.worker_processes)
    cmd:option("-p --pid", "Path to the PID file.")
    cmd:option("-s --signal", "Send signal to a master process: stop, quit, reopen, reload")

    do
      local target = 'configuration_loader'
      local configuration_loader = resty_env.value('APICAST_CONFIGURATION_LOADER')
      local function set_configuration_loader(value)
        return function(args) args[target] = value end
      end

      cmd:mutex(
          cmd:flag('-b --boot',
              "Load configuration on boot.",
              configuration_loader == 'boot'):action(set_configuration_loader('boot')):target('configuration_loader'):init(configuration_loader),
          cmd:flag('-l --lazy',
              "Load configuration on demand.",
              configuration_loader == 'lazy'):action(set_configuration_loader('lazy')):target('configuration_loader'):init(configuration_loader)
      )
    end
    cmd:option("-i --refresh-interval",
        "Cache configuration for N seconds. Using 0 will reload on every request (not for production).",
        resty_env.value('APICAST_CONFIGURATION_CACHE')):convert(tonumber)

    cmd:option("--policy-load-path",
        "Load path where to find policies. Entries separated by `:`.",
        resty_env.value('APICAST_POLICY_LOAD_PATH') or format('%s/policies', apicast_root())
    ):init({}):count('*')
    cmd:mutex(
        cmd:flag('-v --verbose',
            "Increase logging verbosity (can be repeated).")
        :count(("0-%s"):format(#(_M.log_levels) - _M.log_level)),
        cmd:flag('-q --quiet', "Decrease logging verbosity.")
        :count(("0-%s"):format(_M.log_level - 1))
    )
    cmd:option('--log-level', 'Set log level', resty_env.value('APICAST_LOG_LEVEL') or 'warn')
    cmd:option('--log-file', 'Set log file', abspath(resty_env.value('APICAST_LOG_FILE')) or 'stderr')
    cmd:option('--access-log-file', 'Set access log file', abspath(resty_env.value('APICAST_ACCESS_LOG_FILE')) or '/dev/stdout')

    cmd:epilog([[
      Example: apicast start --dev
        This will start APIcast in development mode.]])

    return cmd
end

function _M.new(parser)
    local cmd = configure(parser:command('start', 'Start APIcast'))

    return setmetatable({ parser = parser, cmd = cmd }, mt)
end

function _M:parse(arg)
    return self.cmd:parse(arg)
end


return setmetatable(_M, mt)
