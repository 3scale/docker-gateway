local statsd = {}

local Methods = {}
local mt      = {__index = Methods }

local insert = table.insert
local concat = table.concat
local setmetatable = setmetatable
local queue_name = 'queue'

function Methods:time(bucket, time)
  self:register(bucket, time, "ms")
end

function Methods:count(bucket, n)
  self:register(bucket, n, 'c')
end

function Methods:gauge(bucket, value)
  self:register(bucket, value, 'g')
end

function Methods:set(bucket, value)
  self:register(bucket, value, 's')
end

function Methods:incr(bucket, n)
  self:count(bucket, n or 1)
end

function Methods:register(bucket, amount, suffix)
  local dict = self.shdict

  if self.namespace then bucket = self.namespace .. '.' .. bucket end

  assert(dict:rpush(queue_name, bucket .. ":" .. tostring(amount) .. "|" .. suffix))
end

function Methods:flush(force)
  local dict = self.shdict
  local buffer_size = self.buffer_size
  local batch_size = self.batch_size
  local buffer = {}
  local llen = dict:llen(queue_name) or 0
  local value = llen > buffer_size or force

  while value and #buffer < batch_size do
    value = dict:lpop(queue_name)
    insert(buffer,value)
  end

  if #buffer > 0 then
    local udp = ngx.socket.udp()

    local ok, err = udp:setpeername(self.host, self.port)
    if not ok then ngx.log(ngx.ERR, err) end

    local payload = concat(buffer, "\n")
    ok, err = udp:send(payload)
    ngx.log(ngx.DEBUG, 'statsd ', self.host,':', self.port, ':', payload)
    if not ok then ngx.log(ngx.ERR, err) end

    udp:close()
  end
end

statsd.new = function(host, port, namespace, dict, buffer_size)
  local shdict = ngx.shared[(dict or 'statsd')]

  if not shdict then
    return nil, 'invalid shared dictionary'
  end

  return setmetatable({
    host        = host or '127.0.0.1',
    port        = port or 8125,
    namespace   = namespace, -- or nil
    shdict      = shdict,
    buffer_size = buffer_size or 20,
    batch_size  = buffer_size or 100
  }, mt)
end

return statsd
