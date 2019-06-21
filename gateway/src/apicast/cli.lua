require('apicast.loader')

local command_target = '_cmd'
local parser = require('argparse')() {
    name = os.getenv('ARGV0') or 'apicast',
    description = "APIcast - 3scale API Management Platform Gateway."
}
:command_target(command_target)
:require_command(false)
:handle_options(false)

local _M = { }

local mt = {}

local function load_commands(commands, argparse)
    for i=1, #commands do
        commands[commands[i]] = require('apicast.cli.command.' .. commands[i]).new(argparse)
    end
    return commands
end

_M.commands = load_commands({
  'start',
  'generate',
  'console',
  'push_policy'
}, parser)

function mt.__call(self, arg)
    -- now we parse the options like usual:
    local ok, ret = self.parse(arg)

    if not ok and ret then
        local err = ret
        table.insert(arg, 1, 'start')
        ok, ret = self.parse(arg)
        if not ok then
            ret = err
            table.remove(arg, 1)
       end
    end

    local cmd = ok and ret[command_target]

    if ok and cmd then
        self.commands[cmd](ret)
    elseif ret and type(ret) == 'table' and not next(ret) then
        local start = self.commands.start
        start(start:parse(arg))
    else
        print(ret)
        os.exit(1)
    end
end

function _M.parse(arg)
    return parser:pparse(arg)
end

return setmetatable(_M, mt)
