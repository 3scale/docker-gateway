local PolicyChain = require('apicast.policy_chain')
local resty_url = require('resty.url')
local linked_list = require('apicast.linked_list')
local format = string.format

local function to_url(uri)
    local url = resty_url.parse(uri)

    if url then
        return uri
    elseif uri then
        return format('file:%s', uri)
    end
end

local standalone = assert(PolicyChain.load_policy(
        'apicast.policy.standalone',
        'builtin',
        { url = to_url(context.configuration) }))

if arg then -- running CLI to generate nginx config
    local config, err = standalone:load_configuration() or {}

    if err then
        print(err)
        os.exit(1)
    end

    return linked_list.readonly({
        template = 'http.d/standalone.conf.liquid',
        standalone = config,
        configuration = standalone.url,
    }, config.global)

else -- booting APIcast
    return {
        policy_chain = PolicyChain.new{
            standalone,
        },
        configuration = standalone.url,
    }
end
