local policy = require('apicast.policy')
local _M = policy.new('Explode the OpenID Connect JWT token into HTTP Headers')

local jwt = require("resty.jwt")
local cjson = require "cjson"

-- Valid OpenID Connect fields
local openid_fields = {
  -- Issuer Identifier for the Issuer of the response.
  -- The iss value is a case sensitive URL using the https scheme that contains
  -- scheme, host, and optionally, port number and path components and no query
  -- or fragment components.
  iss = true,

  -- Subject Identifier. A locally unique and never reassigned identifier within
  -- the Issuer for the End-User, which is intended to be consumed by the Client,
  -- e.g., 24400320 or AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT
  -- exceed 255 ASCII characters in length. The sub value is a case sensitive
  -- string.
  sub = true,

  -- Audience(s) that this ID Token is intended for. It MUST contain the OAuth
  -- 2.0 client_id of the Relying Party as an audience value. It MAY also contain
  -- identifiers for other audiences. In the general case, the aud value is an
  -- array of case sensitive strings. In the common special case when there is
  -- one audience, the aud value MAY be a single case sensitive string.
  aud = true,

  -- Expiration time on or after which the ID Token MUST NOT be accepted for
  -- processing. The processing of this parameter requires that the current
  -- date/time MUST be before the expiration date/time listed in the value.
  exp = true,

  -- Time at which the JWT was issued. Its value is a JSON number representing
  -- the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the
  -- date/time.
  iat = true,

  -- Time when the End-User authentication occurred. Its value is a JSON number
  -- representing the number of seconds from 1970-01-01T0:0:0Z as measured in
  -- UTC until the date/time. When a max_age request is made or when auth_time
  -- is requested as an Essential Claim, then this Claim is REQUIRED; otherwise,
  -- its inclusion is OPTIONAL.
  auth_time = true,

  -- String value used to associate a Client session with an ID Token, and to
  -- mitigate replay attacks.
  nonce = true,

  -- Authentication Context Class Reference. String specifying an Authentication
  -- Context Class Reference value that identifies the Authentication Context
  -- Class that the authentication performed satisfied.
  acr = true,

  -- Authentication Methods References. JSON array of strings that are
  -- identifiers for authentication methods used in the authentication.
  amr = true,

  -- Authorized party - the party to which the ID Token was issued. If present,
  -- it MUST contain the OAuth 2.0 Client ID of this party. This Claim is only
  -- needed when the ID Token has a single audience value and that audience
  -- is different than the authorized party. It MAY be included even when the
  -- authorized party is the same as the sole audience. The azp value is a case
  -- sensitive string containing a StringOrURI value.
  azp = true,

  -- End-User's full name in displayable form including all name parts, possibly
  -- including titles and suffixes, ordered according to the End-User's locale
  -- and preferences.
  name = true,

  -- Given name(s) or first name(s) of the End-User. Note that in some cultures,
  -- people can have multiple given names; all can be present, with the names
  -- being separated by space characters.
  given_name = true,

  -- Surname(s) or last name(s) of the End-User. Note that in some cultures,
  -- people can have multiple family names or no family name; all can be present,
  -- with the names being separated by space characters.
  family_name = true,

  -- Middle name(s) of the End-User. Note that in some cultures, people can have
  -- multiple middle names; all can be present, with the names being separated
  -- by space characters. Also note that in some cultures, middle names are not
  -- used.
  middle_name = true,

  -- Casual name of the End-User that may or may not be the same as the
  -- given_name. For instance, a nickname value of Mike might be returned
  -- alongside a given_name value of Michael.
  nickname = true,

  -- Shorthand name by which the End-User wishes to be referred to at the RP,
  -- such as janedoe or j.doe. This value MAY be any valid JSON string including
  -- special characters such as @, /, or whitespace.
  preferred_username = true,

  -- URL of the End-User's profile page.
  profile = true,

  -- URL of the End-User's profile picture.
  picture = true,

  -- URL of the End-User's Web page or blog.
  website = true,

  -- End-User's preferred e-mail address.
  email = true,

  -- True if the End-User's e-mail address has been verified; otherwise false.
  email_verified = true,

  -- End-User's gender. Values defined by this specification are female and male.
  -- Other values MAY be used when neither of the defined values are applicable.
  gender = true,

  -- End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004]
  -- YYYY-MM-DD format.
  birthdate = true,

  -- String from zoneinfo [zoneinfo] time zone database representing the
  -- End-User's time zone.
  zoneinfo = true,

  -- End-User's locale, represented as a BCP47 [RFC5646] language tag.
  locale = true,

  -- End-User's preferred telephone number.
  phone_number = true,

  -- True if the End-User's phone number has been verified; otherwise false.
  phone_number_verified = true,

  -- End-User's preferred postal address.
  address = true,

  -- Time the End-User's information was last updated.
  updated_at = true
}

local function init_config(config)
  local res = {}

  for header, field in pairs(config) do
    if openid_fields[field] then
      res[header] = field
    else
      ngx.log(ngx.WARN, string.format("Skipping HTTP Header '%s' in config since its value '%s' is not recognised as a valid OpenID Connect field.", header, field))
    end
  end

  return res
end

local new = _M.new
function _M.new(config)
  local self = new()
  self.config = init_config(config or {})
  return self
end

function _M:access(context, host)
  local jwt = context.jwt
  if not jwt then
    ngx.log(ngx.WARN, "Could not find any JWT token in the context !")
    return
  end

  for header, field in pairs(self.config) do
    if jwt[field] then
      ngx.req.set_header(header, jwt[field])
    else
      ngx.log(ngx.INFO, "Skipping HTTP Header ", header, " since the matching JWT field ", field, ' is not in the OpenID Connect token')
    end
  end
end

return _M
