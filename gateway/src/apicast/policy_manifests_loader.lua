--- Policy manifests loader
-- Finds the manifests for the builtin policies and the other ones loaded.

local pl_file = require('pl.file')
local pl_dir = require('pl.dir')
local pl_path = require('pl.path')
local cjson = require('cjson')
local format = string.format
local reverse = string.reverse
local find = string.find
local sub = string.sub
local rawset = rawset
local setmetatable = setmetatable
local dir_sep = string.sub(package.config, 1, 1)
local ipairs = ipairs
local pairs = pairs
local insert = table.insert
local policy_loader = require('apicast.policy_loader')

local _M = {}

local builtin_policy_load_path = policy_loader.builtin_policy_load_path
local policy_load_paths = policy_loader.policy_load_paths

local policy_manifest_name = 'apicast-policy.json'

local empty_t = {}

local function dir_iter(dir)
  return ipairs(pl_path.exists(dir) and pl_dir.getdirectories(dir) or empty_t)
end

local manifests_mt = { __index = function(t,k) local v = {}; rawset(t,k, v); return v end }

local function extract_policy_name(dir)
  local reversed = reverse(dir)
  local sep = find(reversed, dir_sep, 1, true)

  return sub(dir, -1*sep + #dir_sep)
end

-- Returns the manifests for all the built-in policies.
local function all_builtin_policy_manifests()
  local manifests = setmetatable({}, manifests_mt)

  for _, policy_dir in dir_iter(builtin_policy_load_path()) do
    local manifest_file = format('%s/%s', policy_dir, policy_manifest_name)
    local manifest = pl_file.read(manifest_file)
    local policy_name = extract_policy_name(policy_dir)
    if manifest then insert(manifests[policy_name], cjson.decode(manifest)) end
  end

  return manifests
end

local function get_manifest_of_builtin_policy(name)
  for _, policy_dir in dir_iter(builtin_policy_load_path()) do
    local manifest_file = format('%s/%s', policy_dir, policy_manifest_name)
    local manifest = pl_file.read(manifest_file)
    local policy_name = extract_policy_name(policy_dir)

    if policy_name == name then
      return cjson.decode(manifest)
    end
  end
end

-- Returns a manifest from a 'version' directory. Policies that are not
-- built-in, are located in a path like policies/my_policy/1.0.0.
-- This function tries to fetch a manifest starting from that `1.0.0` directory.
-- It looks for the json manifest, gets its version, and compares it against the
-- version in the directory.
-- Returns the manifest when found. When it's not present or there's a version
-- mismatch, it returns nil.
local function get_manifest_from_version_dir(version_dir)
  local manifest_file = format('%s/%s', version_dir, policy_manifest_name)
  local manifest = pl_file.read(manifest_file)

  if manifest then
    local decoded_manifest = cjson.decode(manifest)
    local version_in_manifest = decoded_manifest.version
    local version_in_path = pl_path.basename(version_dir)

    if version_in_path == version_in_manifest then
      return decoded_manifest
    else
      ngx.log(ngx.WARN,
        'Could not load ', decoded_manifest.name,
        ' version in manifest is ', version_in_manifest,
        ' but version in path is ', version_in_path)
    end
  end
end

-- Returns all the non-built-in manifests from the paths specified by the user.
-- These paths always follow the same pattern. It contains a directory for each
-- policy, and each of those contain a directory for each version of that
-- policy. The json manifest is in that 'version' directory.
local function all_loaded_policy_manifests()
  local manifests = setmetatable({}, manifests_mt)

  for _, load_path in ipairs(policy_load_paths()) do
    for _, policy_dir in dir_iter(load_path) do
      local name = extract_policy_name(policy_dir)
      for _, version_dir in dir_iter(policy_dir) do
        local manifest = get_manifest_from_version_dir(version_dir)
        if manifest then insert(manifests[name], manifest) end
      end
    end
  end

  return manifests
end

local function get_manifest_of_non_builtin_policy(policy_name, policy_version)
  for _, load_path in ipairs(policy_load_paths()) do
    for _, policy_dir in dir_iter(load_path) do
      local name = extract_policy_name(policy_dir)

      if name == policy_name then
        for _, version_dir in dir_iter(policy_dir) do
          local manifest = get_manifest_from_version_dir(version_dir)
          if manifest and manifest.version == policy_version then
            return manifest
          end
        end
      end
    end
  end
end

--- Get the manifests for all the policies. Both the builtin policies and the
-- ones present in the directories configured as directories that can
-- include policies.
-- @treturn table Manifests for all the policies.
function _M.get_all()
  local manifests = all_builtin_policy_manifests()

  for policy_name, custom_manifests in pairs(all_loaded_policy_manifests()) do

    for _,manifest in ipairs(custom_manifests) do
      insert(manifests[policy_name], manifest)
    end
  end

  return manifests
end

--- Get the manifest of the policy with the given name and version.
-- @tparam string policy_name The policy name
-- @tparam string policy_version The policy version
-- @treturn the manifest of the policy, or nil if it does not exist.
function _M.get(policy_name, policy_version)
  if policy_version == 'builtin' then
    return get_manifest_of_builtin_policy(policy_name)
  else
    return get_manifest_of_non_builtin_policy(policy_name, policy_version)
  end
end

return _M
