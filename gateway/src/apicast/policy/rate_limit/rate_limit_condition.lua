local ipairs = ipairs
local tonumber = tonumber
local match = ngx.re.match

local _M = {}

local function convert_values(key, value)
  local key_local = tonumber(key)
  local value_local = tonumber(value)

  if not key_local then
    return nil, nil, key.." is not number."
  elseif not value_local then
    return nil, nil, value.." is not number."
  end

  return key_local, value_local, nil
end

local function contains(key, value)
  if type(key) == "table" then
    for _, v in ipairs(key) do
      if v == value then
        return true
      end
    end
    return false
  end

  local m, _ = match(key, value)
  return m ~= nil
end

local evaluate_functions = {
  equals = function(key, value)
    return key == value, nil
  end,
  not_equals = function(key, value)
    return key ~= value, nil
  end,
  contains = function(key, value)
    return contains(key, value), nil
  end,
  not_contains = function(key, value)
    return not contains(key, value), nil
  end,
  greater_than = function(key, value)
    local err
    key, value, err = convert_values(key, value)
    if err then
      return false, err
    end
    return key > value, nil
  end,
  greater_than_or_equals = function(key, value)
    local err
    key, value, err = convert_values(key, value)
    if err then
      return false, err
    end
    return key >= value, nil
  end,
  less_than = function(key, value)
    local err
    key, value, err = convert_values(key, value)
    if err then
      return false, err
    end
    return key < value, nil
  end,
  less_than_or_equals = function(key, value)
    local err
    key, value, err = convert_values(key, value)
    if err then
      return false, err
    end
    return key <= value, nil
  end
}

function _M.evaluate(key, options)
  local conditions = options and options.conditions
  local combination = options and options.conditions_combination

  if not conditions then
    return false, "Condition is missing."
  end

  if #conditions > 1 and not combination then
    return false, "Combination is missing."
  end

  for _, condition in ipairs(conditions) do
    local result, err = evaluate_functions[condition.operator](key, condition.value)

    if err then
      return false, err
    end

    if not combination then
      return result, nil
    end

    if result and combination == "or" then
      return true, nil
    end

    if not result and combination == "and" then
      return false, nil
    end
  end

  if combination == "or" then
    return false, nil
  else
    return true, nil
  end
end

return _M
