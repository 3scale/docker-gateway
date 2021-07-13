-- This is a hello_world description.

local policy = require('apicast.policy')
local _M = policy.new('hello_world')

local new = _M.new
--- Initialize a hello_world
-- @tparam [ o p t ] table config Policy configuration.
function _M.new(config)
	local self = new(config)

	if config then

		if config.overwrite == nil then
			self.overwrite = true
		else
			self.overwrite = config.overwrite
		end
		self.secret = config.secret
	end

	return self
end

local function paramsToHeaders(query_params, overwrite)
	for k, v in pairs(query_params) do
		if overwrite == false and ngx.req.get_headers()[k] ~= nil then
			ngx.log(ngx.NOTICE, "existing header found with name " .. k .. " but not overwritten because of setting overwrite is " .. tostring(overwrite))
		else
			ngx.req.set_header(k, v)
		end
	end

	ngx.req.set_uri_args = nil
end

function _M:rewrite(context)

	--read HTTP query params as Lua table
	local query_params = ngx.req.get_uri_args()

	paramsToHeaders(query_params, self.overwrite)

	local secret_header = ngx.req.get_headers()["secret"]
	context.secret_header = secret_header
end

function _M:access(context)

	local secret_header = context.secret_header

	if secret_header ~= self.secret then
		ngx.log(ngx.NOTICE, "request is not authorized, secrets do not match")
		ngx.status = 403
		return ngx.exit(ngx.status)
	else
		ngx.log(ngx.NOTICE, "request is authorized, secrets match")
	end
end

return _M