# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) 
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased]

### Added

- Return 404 back if the upstream is not defined [THREESCALE-3775](https://issues.jboss.org/browse/THREESCALE-3775) [PR #1129](https://github.com/3scale/APIcast/pull/1129)

## [Unreleased]

### Added

- Introduce possibility of specifying policy order restrictions in their schemas. APIcast now shows a warning when those restrictions are not respected [#1088](https://github.com/3scale/APIcast/pull/1088), [THREESCALE-2896](https://issues.jboss.org/browse/THREESCALE-2896)
- Added new parameters to logging policy to allow custom access log [PR #1089](https://github.com/3scale/APIcast/pull/1089), [THREESCALE-1234](https://issues.jboss.org/browse/THREESCALE-1234)[THREESCALE-2876](https://issues.jboss.org/browse/THREESCALE-2876), [PR #1116] (https://github.com/3scale/APIcast/pull/1116)
- Added http_proxy policy to use an HTTP proxy in api_backed calls. [THREESCALE-2696](https://issues.jboss.org/browse/THREESCALE-2696), [PR #1080](https://github.com/3scale/APIcast/pull/1080)
- Option to load service configurations one by one lazily [PR #1099](https://github.com/3scale/APIcast/pull/1099), [THREESCALE-3168](https://issues.jboss.org/browse/THREESCALE-3168)
- New maintenance mode policy, useful for maintenance periods. [PR #1105](https://github.com/3scale/APIcast/pull/1105), [THREESCALE-3189](https://issues.jboss.org/browse/THREESCALE-3189)
- Remove dnsmasq process for APIcast [PR #1090](https://github.com/3scale/APIcast/pull/1090), [THREESCALE-1555](https://issues.jboss.org/browse/THREESCALE-1555)
- Enable liquid operations and original request variable on routing policy [PR #1103](https://github.com/3scale/APIcast/pull/1103) [THREESCALE-3239](https://issues.jboss.org/browse/THREESCALE-3239)
- Allow to use capture function in liquid templates. [PR #1107](https://github.com/3scale/APIcast/pull/1107), [THREESCALE-1911](https://issues.jboss.org/browse/THREESCALE-1911)
- OAuth 2.0 MTLS policy [PR #1101](https://github.com/3scale/APIcast/pull/1101) [Issue #1003](https://github.com/3scale/APIcast/issues/1003)
- Add an option to enable keepalive_timeout on gateway [THREESCALE-2886](https://issues.jboss.org/browse/THREESCALE-2886) [PR #1106](https://github.com/3scale/APIcast/pull/1106)
- Added a new replace path option in routing policy [THREESCALE-3512](https://issues.jboss.org/browse/THREESCALE-3512) [PR #1119](https://github.com/3scale/APIcast/pull/1119) [PR #1121](https://github.com/3scale/APIcast/pull/1121) [PR #1122](https://github.com/3scale/APIcast/pull/1122)
- Added usage metrics on logging policy [PR #1126](https://github.com/3scale/APIcast/pull/1126), [THREESCALE-1234](https://issues.jboss.org/browse/THREESCALE-1234)
- Added owner_id on mapping rule and routing_policy [THREESCALE-3623](https://issues.jboss.org/browse/THREESCALE-3623) [PR #1125](https://github.com/3scale/APIcast/pull/1125)

### Fixed

- Fix issues when OPENTRACING_FORWARD_HEADER was set [PR #1109](https://github.com/3scale/APIcast/pull/1109), [THREESCALE-1660](https://issues.jboss.org/browse/THREESCALE-1660)
- New TLS termination policy [PR #1108](https://github.com/3scale/APIcast/pull/1108), [THREESCALE-2898](https://issues.jboss.org/browse/THREESCALE-2898)
- Fix exception on rate limit policy when window was set as 0. [PR #1113](https://github.com/3scale/APIcast/pull/1108), [THREESCALE-3382](https://issues.jboss.org/browse/THREESCALE-3382)
- Fix issues with escaped characters in uri [THREESCALE-3468](https://issues.jboss.org/browse/THREESCALE-3468) [PR #1123](https://github.com/3scale/APIcast/pull/1123)

## [3.6.0] - 2019-08-30

`3.6.0-rc2` was considered final and became `3.6.0`.

## [3.6.0-rc2] - 2019-07-25

### Fixed

- Fix typos on JWT claim policy jsonschema [PR #1095](https://github.com/3scale/APIcast/pull/1095), [THREESCALE-3046](https://issues.jboss.org/browse/THREESCALE-3046)

## [3.6.0-rc1] - 2019-07-04

### Added

- Extended variables in Liquid template operations [PR #1081](https://github.com/3scale/APIcast/pull/1081), [THREESCALE-2927](https://issues.jboss.org/browse/THREESCALE-2927)


## [3.6.0-beta1] - 2019-06-18

### Added

- You can filter services by endpoint name using Regexp [PR #1022](https://github.com/3scale/APIcast/pull/1022) [THREESCALE-1524](https://issues.jboss.org/browse/THREESCALE-1524)
- "Upstream Connection" policy. It allows to configure several options for the connections to the upstream [PR #1025](https://github.com/3scale/APIcast/pull/1025), [THREESCALE-2166](https://issues.jboss.org/browse/THREESCALE-2166)
- Enable APICAST_EXTENDED_METRICS environment variable to provide additional details [PR #1024](https://github.com/3scale/APIcast/pull/1024) [THREESCALE-2150](https://issues.jboss.org/browse/THREESCALE-2150)
- Add the option to obtain client_id from any JWT claim [THREESCALE-2264](https://issues.jboss.org/browse/THREESCALE-2264) [PR #1034](https://github.com/3scale/APIcast/pull/1034)
- Added `APICAST_PATH_ROUTING_ONLY` variable that allows to perform path-based routing without falling back to the default host-based routing [PR #1035](https://github.com/3scale/APIcast/pull/1035), [THREESCALE-1150](https://issues.jboss.org/browse/THREESCALE-1150)
- Added the option to manage access based on method on Keycloak Policy. [THREESCALE-2236](https://issues.jboss.org/browse/THREESCALE-2236) [PR #1039](https://github.com/3scale/APIcast/pull/1039)
- The Rate Limit policy now supports conditions defined with the "matches" operation. [PR #1051](https://github.com/3scale/APIcast/pull/1051), [THREESCALE-2590](https://issues.jboss.org/browse/THREESCALE-2590)
- Upgrade OpenResty to 1.15.8.1 release.[PR #1049](https://github.com/3scale/APIcast/pull/1049), [THREESCALE-2200](https://issues.jboss.org/browse/THREESCALE-2200)
- Now it is possible to report status codes when using reporting threads [PR #1058](https://github.com/3scale/APIcast/pull/1058), [THREESCALE-2340](https://issues.jboss.org/browse/THREESCALE-2340)
- New Retry policy. Allows to configure retries for calls to the upstream APIs [PR #1057](https://github.com/3scale/APIcast/pull/1057), [THREESCALE-1517](https://issues.jboss.org/browse/THREESCALE-1517)
- JWT claim policy. Allows to allow/deny traffic based on JWT claim constraint [PR #1070](https://github.com/3scale/APIcast/pull/1070), [THREESCALE-2265](https://issues.jboss.org/browse/THREESCALE-2265)

### Fixed

- Fixed incorrect description of the `client` attribute in the Keycloak role check policy [PR #1005](https://github.com/3scale/APIcast/pull/1005), [THREESCALE_1867](https://issues.jboss.org/browse/THREESCALE-1867)
- `export()` now works correctly in policies of the local chain. It was only working in the `rewrite` phase [PR #1023](https://github.com/3scale/APIcast/pull/1023), [THREESCALE-2705](https://issues.jboss.org/browse/THREESCALE-2705)
- The caching policy now works correctly when combined with the 3scale batcher one [PR #1023](https://github.com/3scale/APIcast/pull/1023), [THREESCALE-2705](https://issues.jboss.org/browse/THREESCALE-2705)
- Fixed the name of the 3scale batching policy in the logs. Some logs showed "Caching policy" where it should have said "3scale Batcher" [PR #1029](https://github.com/3scale/APIcast/pull/1029)
- Changed the schema of the IP check policy so it renders correctly in the UI [PR #1026](https://github.com/3scale/APIcast/pull/1026), [THREESCALE-1692](https://issues.jboss.org/browse/THREESCALE-1692)
- Allow uppercase backend API in the service.[PR #1044](https://github.com/3scale/APIcast/pull/1044), [THREESCALE-2540](https://issues.jboss.org/browse/THREESCALE-2540)
- Fixed lock issues on configuration loader when Lazy mode is enabled.[PR #1050](https://github.com/3scale/APIcast/pull/1050), [THREESCALE-2194](https://issues.jboss.org/browse/THREESCALE-2194)
- Fixed multiple x-forwarded-for headers issue on IP Check policy.[PR #1065](https://github.com/3scale/APIcast/pull/1065), [Issue #1061](https://github.com/3scale/APIcast/issues/1061)[THREESCALE-2775](https://issues.jboss.org/browse/THREESCALE-2775)
- APIcast now returns "Auth failed" instead of "Limits Exceeded" for disabled metrics [PR #1066](https://github.com/3scale/APIcast/pull/1066), [THREESCALE-2755](https://issues.jboss.org/browse/THREESCALE-2755)

### Removed

- Checking `aud` JWT claim for app_id when using OIDC integration [PR #1007](https://github.com/3scale/APIcast/pull/1007), [THREESCALE-2263](https://issues.jboss.org/projects/THREESCALE/issues/THREESCALE-2263)

## [3.5.1] - 2019-05-07

Apart from the changes mentioned in this section, this version also includes the changes introduced in `3.5.0-rc1` that were not included in `3.5.0`.

### Added

- Ability to configure client certificate chain depth [PR #1006](https://github.com/3scale/APIcast/pull/1006), [THREESCALE-2383](https://issues.jboss.org/browse/THREESCALE-2383)

### Fixed

- Segfault when normalizing some client certificates [PR #1006](https://github.com/3scale/APIcast/pull/1006)
- Fixed incorrect connection reuse for requests on different domains [PR #1021](https://github.com/3scale/APIcast/pull/1021), [THREESCALE-2205](https://issues.jboss.org/browse/THREESCALE-2205)

## [3.5.0] - 2019-05-07

`3.5.0-beta1` was considered final and became `3.5.0`. Notice that this version does not include the changes introduced in `3.5.0-rc1`.

## [3.5.0-rc1] - 2019-03-29

### Changed

- Do not send OpenResty version in the `Server` response header [PR #997](https://github.com/3scale/APIcast/pull/997), [THREESCALE-1989](https://issues.jboss.org/browse/THREESCALE-1989)
- When using OIDC, the "no-body" option is now set when contacting the 3scale backend. This option helps reducing the workload in the 3scale backend and the network traffic [#998](https://github.com/3scale/APIcast/pull/998), [THREESCALE-2006](https://issues.jboss.org/browse/THREESCALE-2006)

## [3.5.0-beta1] - 2019-03-12

### Changed

- Improve startup time by improving templating performance and caching filesystem access [PR #964](https://github.com/3scale/apicast/pull/964)
- Liquid `default` filter now does not override `false` values [PR #964](https://github.com/3scale/apicast/pull/964)

### Fixed

- Fix 3scale Batcher policy failing to cache and report requests containing app ID only [PR #956](https://github.com/3scale/apicast/pull/956), [THREESCALE-1515](https://issues.jboss.org/browse/THREESCALE-1515)
- Auths against the 3scale backend are now retried when using the 3scale batching policy [PR #961](https://github.com/3scale/apicast/pull/961)
- Fix timeouts when proxying POST requests to an HTTPS upstream using `HTTPS_PROXY` [PR #978](https://github.com/3scale/apicast/pull/978), [THREESCALE-1781](https://issues.jboss.org/browse/THREESCALE-1781)
- The APIcast policy now ensures that its post-action phase only runs when its access phase ran. Not ensuring this was causing a bug that was triggered when combining the APIcast policy with some policies that can deny the request, such as the IP check one. In certain cases, APIcast reported to the 3scale backend in its post-action phase even when other policies denied the request with a 4xx error. [PR #985](https://github.com/3scale/apicast/pull/985)

### Added

- "Matches" operation that can be used when defining conditionals [PR #975](https://github.com/3scale/apicast/pull/975)
- New routing policy that selects an upstream based on the request path, a header, a query argument, or a jwt claim [PR #976](https://github.com/3scale/apicast/pull/976), [PR #983](https://github.com/3scale/apicast/pull/983), [PR #984](https://github.com/3scale/apicast/pull/984), [THREESCALE-1709](https://issues.jboss.org/browse/THREESCALE-1709)
- Added "last" attribute in the mapping rules. When set to true indicates that, if the rule matches, APIcast should not try to match the rules placed after this one [PR #982](https://github.com/3scale/apicast/pull/982), [THREESCALE-1344](https://issues.jboss.org/browse/THREESCALE-1344)
- Added TLS Validation policy to verify TLS Client Certificate against a whitelist. [PR #966](https://github.com/3scale/apicast/pull/966), [THREESCALE-1671](https://issues.jboss.org/browse/THREESCALE-1671)
- New CLI command "push_policy" that pushes a policy schema to the 3scale admin portal [PR #986](https://github.com/3scale/apicast/pull/986), [PR #992](https://github.com/3scale/apicast/pull/992), [THREESCALE-871](https://issues.jboss.org/browse/THREESCALE-871)
- Added support for experimental standalone YAML configuration [PR #926](https://github.com/3scale/apicast/pull/926)
- Environment files now can use global `context` variable to share data [PR #964](https://github.com/3scale/apicast/pull/964)
- Added service id and service name headers in debug context [PR #987](https://github.com/3scale/apicast/pull/987)

### Changed

- The modules used to build conditions have been extracted from the conditional policy so they can be used from other policies [PR #974](https://github.com/3scale/apicast/pull/974).

## [3.4.0] - 2018-12-11

`3.4.0-rc2` was considered final and became `3.4.0`.

## [3.4.0-rc2] - 2018-11-16

### Fixed 

- Fix bug in the Default credentials policy. It was using the default credentials in some cases where it should not [PR #954](https://github.com/3scale/apicast/pull/954), [THREESCALE-1547](https://issues.jboss.org/browse/THREESCALE-1547)

## [3.4.0-rc1] - 2018-11-13

### Fixed

- Fix "nil" being added to the end of URL Path in some cases when using http_proxy [PR #946](https://github.com/3scale/apicast/pull/946)

## [3.4.0-beta1] - 2018-10-24

### Fixed

- Fix `APICAST_PROXY_HTTPS_PASSWORD_FILE` and `APICAST_PROXY_HTTPS_SESSION_REUSE` parameters for Mutual SSL [PR #927](https://github.com/3scale/apicast/pull/927)
- The "allow" mode of the caching policy now accepts the request when it's authorization is not cached [PR #934](https://github.com/3scale/apicast/pull/934), [THREESCALE-1396](https://issues.jboss.org/browse/THREESCALE-1396)
- When using SSL certs with path-based routing enabled, now APIcast falls backs to host-based routing instead of crashing [PR #938](https://github.com/3scale/apicast/pull/938), [THREESCALE-1430](https://issues.jboss.org/browse/THREESCALE-1430)
- Fixed error that happened when loading certain configurations that use OIDC [PR #940](https://github.com/3scale/apicast/pull/940), [THREESCALE-1289](https://issues.jboss.org/browse/THREESCALE-1289)
- The port is now included in the Host header when the request is proxied [PR #942](https://github.com/3scale/apicast/pull/942)

### Added

- Prometheus metrics for: the 3scale batching policy, the upstream API and request response times [PR #902](https://github.com/3scale/apicast/pull/902), [PR #918](https://github.com/3scale/apicast/pull/918), [PR #930](https://github.com/3scale/apicast/pull/930), [THREESCALE-1383](https://issues.jboss.org/browse/THREESCALE-1383)
- Support for path in the upstream URL [PR #905](https://github.com/3scale/apicast/pull/905)
- OIDC Authentication policy (only usable directly by the configuration file) [PR #904](https://github.com/3scale/apicast/pull/904)
- IP check policy. This policy allows to accept or deny requests based on the IP [PR #907](https://github.com/3scale/apicast/pull/907), [PR #923](https://github.com/3scale/apicast/pull/923), [THREESCALE-1353](https://issues.jboss.org/browse/THREESCALE-1353)
- Delete operation in the headers policy [PR #928](https://github.com/3scale/apicast/pull/928), [THREESCALE-1354](https://issues.jboss.org/browse/THREESCALE-1354)
- "Retry-After" header in the response when rate-limited by the 3scale backend [PR #929](https://github.com/3scale/apicast/pull/929), [THREESCALE-1380](https://issues.jboss.org/browse/THREESCALE-1380)

### Changed

- The `threescale_backend_calls` Prometheus metric now includes the response (used to be in `backend_response`) and also the kind of call (auth, authrep, report) [PR #919](https://github.com/3scale/apicast/pull/919), [THREESCALE-1383](https://issues.jboss.org/browse/THREESCALE-1383)
- Performance improvement: replaced some varargs in hot paths [PR #937](https://github.com/3scale/apicast/pull/937)

## [3.3.0] - 2018-10-05

`3.3.0-cr2` was considered final and became `3.3.0`.

- The configuration schema of the rate-limit policy has changed from `3.2.0` so
if you were using it, please adapt your configuration file accordingly.
- The Native OAuth 2.0 flow is deprecated. Please consider using the OIDC
integration instead.
- The new conditional policy is considered experimental. The way conditions are
expressed might change in future releases.

## [3.3.0-cr2] - 2018-09-25

### Fixed

- Handles properly policies that raise an error when initialized [PR #911](https://github.com/3scale/apicast/pull/911), [THREESCALE-1332](https://issues.jboss.org/browse/THREESCALE-1332)

## [3.3.0-cr1] - 2018-09-14

### Fixed

- Set default errlog level when `APICAST_LOG_LEVEL` is empty [PR #868](https://github.com/3scale/apicast/pull/868)
- Correct JWT validation according to [RFC 7523 Section 3](https://tools.ietf.org/html/rfc7523#section-3). Like not required `nbf` claim. [THREESCALE-583](https://issues.jboss.org/browse/THREESCALE-583)
- Mismatch in OIDC issuer when loading configuration through a configuration file [PR #872](https://github.com/3scale/apicast/pull/872)
- When the 3scale referrer filters was enabled, cached requests were not handled correctly [PR #875](https://github.com/3scale/apicast/issues/875)
- Invalid SNI when connecting to 3scale backend over HTTPS [THREESCALE-1269](https://issues.jboss.org/browse/THREESCALE-1269)
- Fix handling --pid and --signal on the CLI [PR #880](https://github.com/3scale/apicast/pull/880)
- Some policies did not have access to the vars exposed when using Liquid (`uri`, `path`, etc.) [PR #891](https://github.com/3scale/apicast/pull/891)
- Fix error when loading certain configurations that use OIDC [PR #893](https://github.com/3scale/apicast/pull/893)
- Fix error that appeared when combining the liquid context debug policy with policies that contain liquid templates [PR #895](https://github.com/3scale/apicast/pull/895)
- Thread safety issues when rendering Liquid templates [PR #896](https://github.com/3scale/apicast/pull/896)

### Added

- Expose `http_method` in Liquid [PR #888](https://github.com/3scale/apicast/pull/888)
- Print error message when OIDC configuration is missing for a request [PR #894](https://github.com/3scale/apicast/pull/894)
- Print whole stderr in 4k chunks when executing external commands [PR #894](https://github.com/3scale/apicast/pull/894)

## [3.3.0-beta2] - 2018-09-03

### Fixed

- Capture permission errors when searching for files on filesystem [PR #865](https://github.com/3scale/apicast/pull/865)

## [3.3.0-beta1] - 2018-08-31

### Added

- OpenTracing support [PR #669](https://github.com/3scale/apicast/pull/669), [THREESCALE-1159](https://issues.jboss.org/browse/THREESCALE-1159)
- Generate new policy scaffold from the CLI [PR #682](https://github.com/3scale/apicast/pull/682)
- 3scale batcher policy [PR #685](https://github.com/3scale/apicast/pull/685), [PR #710](https://github.com/3scale/apicast/pull/710), [PR #757](https://github.com/3scale/apicast/pull/757), [PR #786](https://github.com/3scale/apicast/pull/786), [PR #823](https://github.com/3scale/apicast/pull/823), [THREESCALE-1155](https://issues.jboss.org/browse/THREESCALE-1155)
- Liquid templating support in the headers policy configuration [PR #716](https://github.com/3scale/apicast/pull/716), [PR #845](https://github.com/3scale/apicast/pull/845), [PR #847](https://github.com/3scale/apicast/pull/847), [THREESCALE-1140](https://issues.jboss.org/browse/THREESCALE-1140)
- Ability to modify query parameters in the URL rewriting policy [PR #724](https://github.com/3scale/apicast/pull/724), [PR #818](https://github.com/3scale/apicast/pull/818), [THREESCALE-1139](https://issues.jboss.org/browse/THREESCALE-1139)
- 3scale referrer policy [PR #728](https://github.com/3scale/apicast/pull/728), [PR #777](https://github.com/3scale/apicast/pull/777), [THREESCALE-329](https://issues.jboss.org/browse/THREESCALE-329)
- Liquid templating support in the rate-limit policy [PR #719](https://github.com/3scale/apicast/pull/719), [PR #845](https://github.com/3scale/apicast/pull/845), [PR #847](https://github.com/3scale/apicast/pull/847), [THREESCALE-411](https://issues.jboss.org/browse/THREESCALE-411)
- Default credentials policy [PR #741](https://github.com/3scale/apicast/pull/741), [THREESCALE-586](https://issues.jboss.org/browse/THREESCALE-586)
- Configurable caching for the token introspection policy [PR #656](https://github.com/3scale/apicast/pull/656)
- `APICAST_ACCESS_LOG_FILE` env to make the access log location configurable [PR #743](https://github.com/3scale/apicast/pull/743), [THREESCALE-1148](https://issues.jboss.org/browse/THREESCALE-1148)
- ENV variables to make APIcast listen on HTTPS port [PR #622](https://github.com/3scale/apicast/pull/622) 
- New `ssl_certificate` phase allows policies to provide certificate to terminate HTTPS connection [PR #622](https://github.com/3scale/apicast/pull/622)
- Configurable `auth_type` for the token introspection policy [PR #755](https://github.com/3scale/apicast/pull/755)
- `TimerTask` module to execute recurrent tasks that can be cancelled [PR #782](https://github.com/3scale/apicast/pull/782), [PR #784](https://github.com/3scale/apicast/pull/784), [PR #791](https://github.com/3scale/apicast/pull/791)
- `GC` module that implements a workaround to be able to define `__gc` on tables [PR #790](https://github.com/3scale/apicast/pull/790)
- Policies can define `__gc` metamethod that gets called when they are garbage collected to do cleanup [PR #688](https://github.com/3scale/apicast/pull/688)
- Keycloak Role Check policy [PR #773](https://github.com/3scale/apicast/pull/773), [THREESCALE-1158](https://issues.jboss.org/browse/THREESCALE-1158)
- Conditional policy. This policy includes a condition and a policy chain, and only executes the chain when the condition is true [PR #812](https://github.com/3scale/apicast/pull/812), [PR #814](https://github.com/3scale/apicast/pull/814), [PR #820](https://github.com/3scale/apicast/pull/820)
- Request headers are now exposed in the context available when evaluating Liquid [PR #819](https://github.com/3scale/apicast/pull/819)
- Rewrite URL captures policy. This policy captures arguments in a URL and rewrites the URL using them [PR #827](https://github.com/3scale/apicast/pull/827), [THREESCALE-1139](https://issues.jboss.org/browse/THREESCALE-1139)
- Support for HTTP Proxy [THREESCALE-221](https://issues.jboss.org/browse/THREESCALE-221), [#709](https://github.com/3scale/apicast/issues/709)
- Conditions for the limits of the rate-limit policy [PR #839](https://github.com/3scale/apicast/pull/839)
- `bin/apicast console` to start Lua REPL with APIcast code loaded [PR #853](https://github.com/3scale/apicast/pull/853)
- Liquid Context Debugging policy. It's a policy only meant for debugging purposes, returns the context available when evaluating liquid [PR #849](https://github.com/3scale/apicast/pull/849)
- Logging policy. It allows to enable/disable access logs per service [PR #856](https://github.com/3scale/apicast/pull/856), [THREESCALE-1148](https://issues.jboss.org/browse/THREESCALE-1148)
- Support JWK through OIDC Discovery [PR #850](https://github.com/3scale/apicast/pull/850)
- Initial Prometheus metrics policy (backend responses and nginx metrics) [PR #860](https://github.com/3scale/apicast/pull/860), [THREESCALE-1230](https://issues.jboss.org/browse/THREESCALE-1230)

### Changed

- `THREESCALE_PORTAL_ENDPOINT` and `THREESCALE_CONFIG_FILE` are not required anymore [PR #702](https://github.com/3scale/apicast/pull/702)
- The `scope` of the Rate Limit policy is `service` by default [PR #704](https://github.com/3scale/apicast/pull/704)
- Decoded JWTs are now exposed in the policies context by the APIcast policy [PR #718](https://github.com/3scale/apicast/pull/718)
- Upgraded OpenResty to 1.13.6.2, uses OpenSSL 1.1 [PR #733](https://github.com/3scale/apicast/pull/733)
- Use forked `resty.limit.count` that uses increments instead of decrements [PR #758](https://github.com/3scale/apicast/pull/758), [PR 843](https://github.com/3scale/apicast/pull/843)
- Rate Limit policy to take into account changes in the config [PR #703](https://github.com/3scale/apicast/pull/703)
- The regular expression for mapping rules has been changed, so that special characters are accepted in the wildcard values for path [PR #714](https://github.com/3scale/apicast/pull/714)
- Call `init` and `init_worker` on all available policies regardless they are used or not [PR #770](https://github.com/3scale/apicast/pull/770)
- Cache loaded policies. Loading one policy several times will use the same instance [PR #770](https://github.com/3scale/apicast/pull/770)
- Load all policies into cache when starting APIcast master process. [PR #770](https://github.com/3scale/apicast/pull/770)
- `init` and `init_worker` phases are executed on the policy module, not the instance of a policy with a configuration [PR #770](https://github.com/3scale/apicast/pull/770)
- `timer_resolution` set only in development environment [PR #815](https://github.com/3scale/apicast/pull/815)
- The rate-limit policy, when `redis_url` is empty, now applies per-gateway limits instead of trying to use a localhost Redis [PR #842](https://github.com/3scale/apicast/pull/842)
- Changed the display name of some policies. This only affects how the name shows in the UI [THREESCALE-1232](https://issues.jboss.org/browse/THREESCALE-1232)

### Fixed

- Do not crash when initializing unreachable/invalid DNS resolver [PR #730](https://github.com/3scale/apicast/pull/730)
- Reporting only 50% calls to 3scale backend when using OIDC [PR #774](https://github.com/3scale/apicast/pull/774), [THREESCALE-1080](https://issues.jboss.org/browse/THREESCALE-1080)
- Building container image on OpenShift 3.9 [PR #810](https://github.com/3scale/apicast/pull/810), [THREESCALE-1138](https://issues.jboss.org/browse/THREESCALE-1138)
- Rate Limit policy to define multiple limiters of the same type [PR #825](https://github.com/3scale/apicast/pull/825)
- Fix `exclusiveMinimum` field for `conn` property in the rate-limit JSON schema [PR #832](https://github.com/3scale/apicast/pull/832)
- Skip invalid policies in the policy chain [PR #854](https://github.com/3scale/apicast/pull/854)

## [3.2.1] - 2018-06-26

### Changed

- `APICAST_BACKEND_CACHE_HANDLER` environment variable is now deprecated. Use caching policy instead. `APICAST_CUSTOM_CONFIG`, `APICAST_MODULE` environment variables are now deprecated. Use policies instead. [PR #746](https://github.com/3scale/apicast/pull/746), [THREESCALE-1034](https://issues.jboss.org/browse/THREESCALE-1034)
- Path routing feature enabled by the `APICAST_PATH_ROUTING` environment variable is not considered experimental anymore.

### Fixed

- Reporting only 50% calls to 3scale backend when using OIDC [PR #779](https://github.com/3scale/apicast/pull/779)

## [3.2.0] - 2018-06-04

3.2.0-rc2 was considered final and became 3.2.0.

## [3.2.0-rc2] - 2018-05-11

### Added

- Default value for the `caching_type` attribute of the caching policy config schema [#691](https://github.com/3scale/apicast/pull/691), [THREESCALE-845](https://issues.jboss.org/browse/THREESCALE-845)

### Fixed

- Fixed set of valid values for the exit param of the Echo policy [PR #684](https://github.com/3scale/apicast/pull/684/)

### Changed

- The schema of the rate-limit policy has been adapted so it can be rendered by `react-jsonschema-form`, a library used in the 3scale UI. This is a breaking change. [PR #696](https://github.com/3scale/apicast/pull/696), [THREESCALE-888](https://issues.jboss.org/browse/THREESCALE-888)
- The upstream policy now performs the rule matching in the rewrite phase. This allows combining it with the URL rewriting policy – upstream policy regex will be matched against the original path if upstream policy is placed before URL rewriting in the policy chain, and against the rewritten path otherwise [PR #690](https://github.com/3scale/apicast/pull/690), [THREESCALE-852](https://issues.jboss.org/browse/THREESCALE-852)

## [3.2.0-rc1] - 2018-04-24

### Added

- Rate Limit policy [PR #648](https://github.com/3scale/apicast/pull/648)
- Documented restrictions in the position in the chain for some policies [PR #675](https://github.com/3scale/apicast/pull/675), [THREESCALE-799](https://issues.jboss.org/browse/THREESCALE-799)

### Fixed

- `export()` now works correctly in policies of the local chain [PR #673](https://github.com/3scale/apicast/pull/673)
- caching policy now works correctly when placed after the apicast policy in the chain [PR #674](https://github.com/3scale/apicast/pull/674)
- OpenTracing support [PR #669](https://github.com/3scale/apicast/pull/669)

### Changed

- descriptions in `oneOf`s in policy manifests have been replaced with titles [PR #663](https://github.com/3scale/apicast/pull/663)
- `resty.balancer` doesn't fall back to the port `80` by default. If the port is missing, `apicast.balancer` sets the default port for the scheme of the `proxy_pass` URL [PR #662](https://github.com/3scale/apicast/pull/662)

## [3.2.0-beta3] - 2018-03-20

### Fixed

- `ljsonschema` is only used in testing but was required in production also [PR #660](https://github.com/3scale/apicast/pull/660)

## [3.2.0-beta2] - 2018-03-19

### Added

- New property `summary` in the policy manifests [PR #633](https://github.com/3scale/apicast/pull/633)
- OAuth2.0 Token Introspection policy [PR #619](https://github.com/3scale/apicast/pull/619)
- New `metrics` phase that runs when prometheus is collecting metrics [PR #629](https://github.com/3scale/apicast/pull/629)
- Validation of policy configs both in integration and unit tests [PR #646](https://github.com/3scale/apicast/pull/646)
- Option to avoid refreshing the config when using the lazy loader with `APICAST_CONFIGURATION_CACHE` < 0 [PR #657](https://github.com/3scale/apicast/pull/657)

### Fixed

- Error loading policy chain configuration JSON with null value [PR #626](https://github.com/3scale/apicast/pull/626)
- Splitted `resolv.conf` in lines,to avoid commented lines  [PR #618](https://github.com/3scale/apicast/pull/618)
- Avoid `nameserver` repetion from `RESOLVER` variable and `resolv.conf` file [PR #636](https://github.com/3scale/apicast/pull/636)
- Bug in URL rewriting policy that ignored the `commands` attribute in the policy manifest [PR #641](https://github.com/3scale/apicast/pull/641)
- Skip comentaries after `search` values in resolv.conf [PR #635](https://github.com/3scale/apicast/pull/635)
- Bug that prevented using `CONFIGURATION_CACHE_LOADER=boot` without specifying `APICAST_CONFIGURATION_CACHE` in staging [PR #651](https://github.com/3scale/apicast/pull/651), [THREESCALE-756](https://issues.jboss.org/browse/THREESCALE-756).
- `typ` is verified when it's present in keycloak tokens [PR #658](https://github.com/3scale/apicast/pull/658)

### Changed

- `summary` is now required in policy manifests [PR #655](https://github.com/3scale/apicast/pull/655)

## [3.2.0-beta1] - 2018-02-20

### Added

- Definition of JSON schemas for policy configurations [PR #522](https://github.com/3scale/apicast/pull/522), [PR #601](https://github.com/3scale/apicast/pull/601)
- URL rewriting policy [PR #529](https://github.com/3scale/apicast/pull/529), [THREESCALE-618](https://issues.jboss.org/browse/THREESCALE-618)
- Liquid template can find files in current folder too [PR #533](https://github.com/3scale/apicast/pull/533)
- `bin/apicast` respects `APICAST_OPENRESTY_BINARY` and `TEST_NGINX_BINARY` environment [PR #540](https://github.com/3scale/apicast/pull/540)
- Caching policy [PR #546](https://github.com/3scale/apicast/pull/546), [PR #558](https://github.com/3scale/apicast/pull/558), [THREESCALE-587](https://issues.jboss.org/browse/THREESCALE-587), [THREESCALE-550](https://issues.jboss.org/browse/THREESCALE-550)
- New phase: `content` for generating content or getting the upstream response [PR #535](https://github.com/3scale/apicast/pull/535)
- Upstream policy [PR #562](https://github.com/3scale/apicast/pull/562), [THREESCALE-296](https://issues.jboss.org/browse/THREESCALE-296)
- Policy JSON manifest [PR #565](https://github.com/3scale/apicast/pull/565)
- SOAP policy [PR #567](https://github.com/3scale/apicast/pull/567), [THREESCALE-553](https://issues.jboss.org/browse/THREESCALE-553)
- Ability to set custom directories to load policies from [PR #581](https://github.com/3scale/apicast/pull/581)
- CLI is running with proper log level set by `APICAST_LOG_LEVEL` [PR #585](https://github.com/3scale/apicast/pull/585)
- 3scale configuration (staging/production) can be passed as `-3` or `--channel` on the CLI [PR #590](https://github.com/3scale/apicast/pull/590)
- APIcast CLI loads environments defined by `APICAST_ENVIRONMENT` variable [PR #590](https://github.com/3scale/apicast/pull/590)
- Endpoint in management API to retrieve all the JSON manifests of the policies [PR #592](https://github.com/3scale/apicast/pull/592)
- Development environment (`--dev`) starts with Echo policy unless some configuration is passed [PR #593](https://github.com/3scale/apicast/pull/593)
- Added support for passing whole configuration as Data URL [PR #593](https://github.com/3scale/apicast/pull/593)
- More complete global environment when loading environment policies [PR #596](https://github.com/3scale/apicast/pull/596)
- Support for Client Certificate authentication with upstream servers [PR #610](https://github.com/3scale/apicast/pull/610), [THREESCALE-328](http://issues.jboss.org/browse/THREESCALE-328)

### Fixed

- Detecting local rover installation from the CLI [PR #519](https://github.com/3scale/apicast/pull/519)
- Use more `command` instead of `which` to work in plain shell [PR #521](https://github.com/3scale/apicast/pull/521)
- Fixed rockspec so APIcast can be installed by luarocks [PR #523](https://github.com/3scale/apicast/pull/523), [PR #538](https://github.com/3scale/apicast/pull/538)
- Fix loading renamed APIcast code [PR #525](https://github.com/3scale/apicast/pull/525)
- Fix `apicast` command when installed from luarocks [PR #527](https://github.com/3scale/apicast/pull/527)
- Fix lua docs formatting in the CORS policy [PR #530](https://github.com/3scale/apicast/pull/530)
- `post_action` phase not being called in the policy_chain [PR #539](https://github.com/3scale/apicast/pull/539)
- Failing to execute `libexec/boot` on some systems [PR #544](https://github.com/3scale/apicast/pull/544)
- Detect number of CPU cores in containers by using `nproc` [PR #554](https://github.com/3scale/apicast/pull/554)
- Running with development config in Docker [PR #555](https://github.com/3scale/apicast/pull/555)
- Fix setting twice the headers in a pre-flight request in the CORS policy [PR #570](https://github.com/3scale/apicast/pull/570)
- Fix case where debug headers are returned without enabling the option [PR #577](https://github.com/3scale/apicast/pull/577)
- Fix errors loading openresty libraries when rover is active [PR #598](https://github.com/3scale/apicast/pull/598)
- Passthrough "invalid" headers [PR #612](https://github.com/3scale/apicast/pull/612), [THREESCALE-630](https://issues.jboss.org/browse/THREESCALE-630)
- Fix using relative path for access and error log [THREESCALE-1090](https://issues.jboss.org/browse/THREESCALE-1090)

### Changed

- Consolidate apicast-0.1-0.rockspec into apicast-scm-1.rockspec [PR #526](https://github.com/3scale/apicast/pull/526)
- Deprecated `Configuration.extract_usage` in favor of `Service.get_usage` [PR #531](https://github.com/3scale/apicast/pull/531)
- Extract Test::APIcast to own package on CPAN [PR #528](https://github.com/3scale/apicast/pull/528)
- Load policies by the APIcast loader instead of changing load path [PR #532](https://github.com/3scale/apicast/pull/532), [PR #536](https://github.com/3scale/apicast/pull/536)
- Add `src` directory to the Lua load path when using CLI [PR #533](https://github.com/3scale/apicast/pull/533)
- Move rejection reason parsing from CacheHandler to Proxy [PR #541](https://github.com/3scale/apicast/pull/541)
- Propagate full package.path and cpath from the CLI to Nginx [PR #538](https://github.com/3scale/apicast/pull/538)
- `post_action` phase now shares `ngx.ctx` with the main request [PR #539](https://github.com/3scale/apicast/pull/539)
- Decrease nginx timer resolution to improve performance and enable PCRE JIT [PR #543](https://github.com/3scale/apicast/pull/543)
- Moved `proxy_pass` into new internal location `@upstream` [PR #535](https://github.com/3scale/apicast/pull/535)
- Split 3scale authorization to rewrite and access phase [PR #556](https://github.com/3scale/apicast/pull/556)
- Extract `mapping_rule` module from the `configuration` module [PR #571](https://github.com/3scale/apicast/pull/571)
- Renamed `apicast/policy/policy.lua` to `apicast/policy.lua` [PR #569](https://github.com/3scale/apicast/pull/569)
- Sandbox loading policies [PR #566](https://github.com/3scale/apicast/pull/566)
- Extracted `usage` and `mapping_rules_matcher` modules so they can be used from policies [PR #580](https://github.com/3scale/apicast/pull/580)
- Renamed all `apicast/policy/*/policy.lua` to `apicast/policy/*/init.lua` to match Lua naming [PR #579](https://github.com/3scale/apicast/pull/579)
- Environment configuration can now define the configuration loader or cache [PR #590](https://github.com/3scale/apicast/pull/590).
- APIcast starts with "boot" configuration loader by default (because production is the default environment) [PR #590](https://github.com/3scale/apicast/pull/590).
- Deprecated `APICAST_SERVICES` in favor of `APICAST_SERVICES_LIST` but provides backwards compatibility [PR #549](https://github.com/3scale/apicast/pull/549)
- Deprecated `APICAST_PATH_ROUTING_ENABLED` in favor of `APICAST_PATH_ROUTING` but provides backwards compatibility [PR #549](https://github.com/3scale/apicast/pull/549)

## [3.2.0-alpha2] - 2017-11-30

### Added

- New policy chains system. This allows users to write custom policies to configure what Apicast can do on each of the Nginx phases [PR #450](https://github.com/3scale/apicast/pull/450), [THREESCALE-553](https://issues.jboss.org/browse/THREESCALE-553)
- Resolver can resolve nginx upstreams [PR #478](https://github.com/3scale/apicast/pull/478)
- Add `resolver` directive in the nginx configuration [PR #508](https://github.com/3scale/apicast/pull/508)
- Calls 3scale backend with the 'no_body' option enabled. This reduces network traffic in cases where APIcast does not need to parse the response body [PR #483](https://github.com/3scale/apicast/pull/483)
- Methods to modify policy chains [PR #505](https://github.com/3scale/apicast/pull/505)
- Ability to load several environment configurations [PR #504](https://github.com/3scale/apicast/pull/504)
- Ability to configure policy chain from the environment configuration [PR #496](https://github.com/3scale/apicast/pull/496)
- Load environment variables defined in the configuration [PR #507](https://github.com/3scale/apicast/pull/507)
- Allow configuration of the echo/management/fake backend ports [PR #506](https://github.com/3scale/apicast/pull/506)
- Headers policy [PR #497](https://github.com/3scale/apicast/pull/497), [THREESCALE-552](https://issues.jboss.org/browse/THREESCALE-552)
- CORS policy [PR #487](https://github.com/3scale/apicast/pull/487), [THREESCALE-279](https://issues.jboss.org/browse/THREESCALE-279)
- Detect number of CPU shares when running on Kubernetes [PR #600](https://github.com/3scale/apicast/pull/600)

### Changed

- Namespace all APIcast code in `apicast` folder. Possible BREAKING CHANGE for some customizations. [PR #486](https://github.com/3scale/apicast/pull/486)
- CLI ignores environment variables that are empty strings [PR #504](https://github.com/3scale/apicast/pull/504)

### Fixed

- Loading installed luarocks from outside rover [PR #503](https://github.com/3scale/apicast/pull/503)
- Support IPv6 addresses in `/etc/resolv.conf` [PR #511](https://github.com/3scale/apicast/pull/511)
- Fix possible 100% CPU usage when starting APIcast and manipulating filesystem [PR #547](https://github.com/3scale/apicast/pull/547)

## [3.2.0-alpha1]

### Added

- Experimental option for true out of band reporting (`APICAST_REPORTING_WORKERS`) [PR #290](https://github.com/3scale/apicast/pull/290), [THREESCALE-365](https://issues.jboss.org/browse/THREESCALE-365)
- `/status/info` endpoint to the Management API [PR #290](https://github.com/3scale/apicast/pull/290)
- `/_threescale/healthz` endpoint returns a success status code, this is used for health checking in kubernetes environments [PR #285](https://github.com/3scale/apicast/pull/285)
- Usage limit errors are now configurable to distinguish them from other authorization errors [PR #453](https://github.com/3scale/apicast/pull/453), [THREESCALE-638](https://issues.jboss.org/browse/THREESCALE-638).
- Templating nginx configuration with liquid. [PR #449](https://github.com/3scale/apicast/pull/449)

### Changed

- Upgraded to OpenResty 1.11.2.5-1 [PR #428](https://github.com/3scale/apicast/pull/428)
- `/oauth/token` endpoint returns an error status code, when the access token couldn't be stored in 3scale backend [PR #436](https://github.com/3scale/apicast/pull/436)]
- URI params in POST requests are now taken into account when matching mapping rules [PR #437](https://github.com/3scale/apicast/pull/437)
- Increased number of background timers and connections in the cosocket pool [PR #290](https://github.com/3scale/apicast/pull/290)
- Make OAuth tokens TTL configurable [PR #448](https://github.com/3scale/apicast/pull/448)
- Detect when being executed in Test::Nginx and use default backend accordingly [PR #458](https://github.com/3scale/apicast/pull/458)
- Update the s2i-openresty image to have the same path (`/opt/app-root/src`) in all images [PR #460](https://github.com/3scale/apicast/pull/460)
- Launcher scripts are now Perl + Lua instead of Shell [PR #449](https://github.com/3scale/apicast/pull/449)
- Unify how to connect to 3scale backend [PR #456](https://github.com/3scale/apicast/pull/456)
- Upgraded OpenResty to 1.13.6.1 [PR #480](https://github.com/3scale/apicast/pull/480), [THREESCALE-362](https://issues.jboss.org/browse/THREESCALE-362)

### Fixed

- Request headers are not passed to the backend, preventing sending invalid Content-Type to the access token store endpoint [PR #433](https://github.com/3scale/apicast/pull/433), [THREESCALE-372](https://issues.jboss.org/browse/THREESCALE-372)
- Live and ready endpoints now set correct Content-Type header in the response[PR #441](https://github.com/3scale/apicast/pull/441), [THREESCALE-377](https://issues.jboss.org/browse/THREESCALE-377)

## [3.1.0] - 2017-10-27
- 3.1.0-rc2 was considered final and became 3.1.0.

## [3.1.0-rc2] - 2017-09-29

### Fixed

- Request headers are not passed to the backend, preventing sending invalid Content-Type to the access token store endpoint [PR #433](https://github.com/3scale/apicast/pull/433)

## [3.1.0-rc1] - 2017-09-14

### Added

- Support for extending APIcast location block with snippets of nginx configuration [PR #407](https://github.com/3scale/apicast/pull/407)

### Fixed

- Crash on empty OIDC Issuer endpoint [PR #408](https://github.com/3scale/apicast/pull/408)
- Handle partial credentials [PR #409](https://github.com/3scale/apicast/pull/409)
- Crash when configuration endpoint was missing [PR #417](https://github.com/3scale/apicast/pull/417)
- Fix double queries to not fully qualified domains [PR #419](https://github.com/3scale/apicast/pull/419)
- Fix caching DNS queries with scope (like on OpenShift) [PR #420](https://github.com/3scale/apicast/pull/420)

### Changed

- `THREESCALE_DEPLOYMENT_ENV` defaults to `production` [PR #406](https://github.com/3scale/apicast/pull/406)
- OIDC is now used based on settings on the API Manager [PR #405](https://github.com/3scale/apicast/pull/405)
- No limit on body size from the client sent to the server [PR #410](https://github.com/3scale/apicast/pull/410)
- Print module loading errors only when it failed to load [PR #415](https://github.com/3scale/apicast/pull/415)
- `bin/busted` rewritten to support different working directories [PR #418](https://github.com/3scale/apicast/pull/418)
- dnsmasq started in docker will not forward queries without domain [PR #421](https://github.com/3scale/apicast/pull/421)

## [3.1.0-beta2] - 2017-08-21

### Added

- Ability to configure how to cache backend authorizations [PR #396](https://github.com/3scale/apicast/pull/396)

### Fixed

- Not loading services when APICAST\_SERVICES is empty [PR #401](https://github.com/3scale/apicast/pull/401), [THREESCALE-281](https://issues.jboss.org/browse/THREESCALE-281)

## [3.1.0-beta1] - 2017-07-21

### Fixed

- Fixed CVE-2017-7512 [PR #393](https://github.com/3scale/apicast/pull/392)

### Changed

- APIcast module `balancer` method now accepts optional balancer [PR #362](https://github.com/3scale/apicast/pull/362)
- Extracted lua-resty-url [PR #384](https://github.com/3scale/apicast/pull/384)
- Extracted lua-resty-env [PR #386](https://github.com/3scale/apicast/pull/386)
- Do not load all services when APICAST\_SERVICES is set [PR #388](https://github.com/3scale/apicast/pull/388)

### Added

- APIcast published to [luarocks.org](https://luarocks.org/modules/3scale/apicast) [PR #366](https://github.com/3scale/apicast/pull/366)
- Support for passing remote configuratio URL through the CLI [PR #389](https://github.com/3scale/apicast/pull/389)
- CLI flag -b to load configuration on boot [PR #389](https://github.com/3scale/apicast/pull/389)
- OIDC support [PR #382](https://github.com/3scale/apicast/pull/382)

### Removed

- Keycloak / RH SSO integration replaced with OIDC [PR #382](https://github.com/3scale/apicast/pull/382)

## [3.1.0-alpha1] - 2017-05-05

### Changed

- Bump OpenResty version to [1.11.2.3](https://github.com/3scale/s2i-openresty/releases/tag/1.11.2.3-1) [PR #359](https://github.com/3scale/apicast/pull/359) 
- Upgraded lua-resty-http and lua-resty-jwt [PR #361](https://github.com/3scale/apicast/pull/361)

### Added

- Experimental caching proxy to the http client [PR #357](https://github.com/3scale/apicast/pull/357)

### Changed

- Print better errors when module loading fails [PR #360](https://github.com/3scale/apicast/pull/360)

## [3.0.0] - 2017-04-04

### Added

- Support for loading configration from custom URL [PR #323](https://github.com/3scale/apicast/pull/323)
- Turn on SSL/TLS validation by `OPENSSL_VERIFY` environment variable [PR #332](https://github.com/3scale/apicast/pull/332)
- Load trusted CA chain certificates [PR #332](https://github.com/3scale/apicast/pull/332)
- Support HTTP Basic authentication for client credentials when authorizing with RH-SSO [PR #336](https://github.com/3scale/apicast/pull/336)
- Show more information about the error when the module load fails [PR #348](https://github.com/3scale/apicast/pull/348)

### Changed

- Use `RESOLVER` before falling back to `resolv.conf` [PR #324](https://github.com/3scale/apicast/pull/324)
- Improve error logging when failing to download configuration [PR #335](https://github.com/3scale/apicast/pull/325)
- Service hostnames are normalized to lower case [PR #336](https://github.com/3scale/apicast/pull/326)
- Don't attempt to perform post\_action when request was handled without authentication [PR #343](https://github.com/3scale/apicast/pull/343)
- Store authorization responses with a ttl, if sent [PR #341](https://github.com/3scale/apicast/pull/341)

### Fixed

- Do not return stale service configuration when new one is available [PR #333](https://github.com/3scale/apicast/pull/333)
- Memory leak in every request [PR #339](https://github.com/3scale/apicast/pull/339)
- Remove unnecessary code and comments [PR #344](https://github.com/3scale/apicast/pull/344)
- JWT expiry not taken into account in authorization response cache [PR #283](https://github.com/3scale/apicast/pull/283) / [Issue #309](https://github.com/3scale/apicast/issues/309) / Fixed by [PR #341](https://github.com/3scale/apicast/pull/341)
- Memory leak in round robin balancer [PR #345](https://github.com/3scale/apicast/pull/345)
- Error when trying to determine status of failed request when downloading configuration [PR #350](https://github.com/3scale/apicast/pull/350)

## [3.0.0-beta3] - 2017-03-20

### Changed

- Use per request configuration when cache is disabled [PR #289](https://github.com/3scale/apicast/pull/289)
- Automatically expose all environment variables starting with `APICAST_` or `THREESCALE_` to nginx [PR #292](https://github.com/3scale/apicast/pull/292)
- Error log to show why downloading configuration failed [PR #306](https://github.com/3scale/apicast/pull/306)

### Added

- Backend HTTP client that uses cosockets [PR #295](https://github.com/3scale/apicast/pull/295)
- Ability to customize main section of nginx configuration (and expose more env variables) [PR #292](https://github.com/3scale/apicast/pull/292)
- Ability to lock service to specific configuration version [PR #293](https://github.com/3scale/apicast/pull/292)
- Ability to use Redis DB and password via `REDIS_URL` [PR #303](https://github.com/3scale/apicast/pull/303)
- Ability to Authenticate against API using RHSSO and OpenID Connect [PR #283](https://github.com/3scale/apicast/pull/283)

### Fixed
- `http_ng` client supports auth passsed in the url, and default client options if the request options are missing for methods with body (POST, PUT, etc.) [PR #310](https://github.com/3scale/apicast/pull/310)
- Fixed lazy configuration loader to recover from failures [PR #313](https://github.com/3scale/apicast/pull/313)
- Fixed undefined variable `p` in post\_action [PR #316](https://github.com/3scale/apicast/pull/316)
- Fixed caching of negative ttl by dnsmasq [PR #318](https://github.com/3scale/apicast/pull/318)

### Removed

- Removed support for sending Request logs [PR #296](https://github.com/3scale/apicast/pull/296)
- Support for parallel DNS query [PR #311](https://github.com/3scale/apicast/pull/311)

### Known Issues

- JWT expiry not taken into account in authorization response cache [PR #283](https://github.com/3scale/apicast/pull/283) / [Issue #309](https://github.com/3scale/apicast/issues/309)

## [3.0.0-beta2] - 2017-03-08

### Fixed

- Reloading of configuration with every request when cache is disabled [PR #287](https://github.com/3scale/apicast/pull/287)
- Auth caching is not used when OAuth method is used [PR #304](https://github.com/3scale/apicast/pull/304)

## [3.0.0-beta1] - 2017-03-03

### Changed
- Lazy load DNS resolver to improve performance [PR #251](https://github.com/3scale/apicast/pull/251)
- Execute queries to all defined nameservers in parallel [PR #260](https://github.com/3scale/apicast/pull/260)
- `RESOLVER` ENV variable overrides all other nameservers detected from `/etc/resolv.conf` [PR #260](https://github.com/3scale/apicast/pull/260)
- Use stale DNS cache when there is a query in progress for that record [PR #260](https://github.com/3scale/apicast/pull/260)
- Bump s2i-openresty to 1.11.2.2-2 [PR #260](https://github.com/3scale/apicast/pull/260)
- Echo API on port 8081 listens accepts any Host [PR #268](https://github.com/3scale/apicast/pull/268)
- Always use DNS search scopes [PR #271](https://github.com/3scale/apicast/pull/271)
- Reduce use of global objects [PR #273](https://github.com/3scale/apicast/pull/273)
- Configuration is using LRU cache [PR #274](https://github.com/3scale/apicast/pull/274)
- Management API not opened by default [PR #276](https://github.com/3scale/apicast/pull/276)
- Management API returns ready status with no services [PR #]()

### Added

* Danger bot to check for consistency in Pull Requests [PR #265](https://github.com/3scale/apicast/pull/265)
* Start local caching DNS server in the container [PR #260](https://github.com/3scale/apicast/pull/260)
* Management API to show the DNS cache [PR #260](https://github.com/3scale/apicast/pull/260)
* Extract correct Host header from the backend endpoint when backend host not provided [PR #267](https://github.com/3scale/apicast/pull/267)
* `APICAST_CONFIGURATION_CACHE` environment variable [PR #270](https://github.com/3scale/apicast/pull/270)
* `APICAST_CONFIGURATION_LOADER` environment variable [PR #270](https://github.com/3scale/apicast/pull/270)

### Removed

* Support for downloading configuration via curl [PR #266](https://github.com/3scale/apicast/pull/266)
* `AUTO_UPDATE_INTERVAL` environment variable [PR #270](https://github.com/3scale/apicast/pull/270)
* `APICAST_RELOAD_CONFIG` environment variable [PR #270](https://github.com/3scale/apicast/pull/270)
* `APICAST_MISSING_CONFIGURATION` environment variable [PR #270](https://github.com/3scale/apicast/pull/270)

## [3.0.0-alpha2] - 2017-02-06

### Added
- A way to override backend endpoint [PR #248](https://github.com/3scale/apicast/pull/248)

### Changed
- Cache all calls to `os.getenv` via custom module [PR #231](https://github.com/3scale/apicast/pull/231)
- Bump s2i-openresty to 1.11.2.2-1 [PR #239](https://github.com/3scale/apicast/pull/239)
- Use resty-resolver over nginx resolver for HTTP [PR #237](https://github.com/3scale/apicast/pull/237)
- Use resty-resolver over nginx resolver for Redis [PR #237](https://github.com/3scale/apicast/pull/237)
- Internal change to reduce global state [PR #233](https://github.com/3scale/apicast/pull/233)

### Fixed
- [OAuth] Return correct state value back to client

### Removed
- Nginx resolver directive auto detection. Rely on internal DNS resolver [PR #237](https://github.com/3scale/apicast/pull/237)

## [3.0.0-alpha1] - 2017-01-16
### Added
- A CHANGELOG.md to track important changes
- User-Agent header with APIcast version and system information [PR #214](https://github.com/3scale/apicast/pull/214)
- Try to load configuration from V2 API [PR #193](https://github.com/3scale/apicast/pull/193)

### Changed
- Require openresty 1.11.2 [PR #194](https://github.com/3scale/apicast/pull/194)
- moved development from `v2` branch to `master` [PR #209](https://github.com/3scale/apicast/pull/209)
- `X-3scale-Debug` HTTP header now uses Service Token [PR #217](https://github.com/3scale/apicast/pull/217)

## [2.0.0] - 2016-11-29
### Changed
- Major rewrite using JSON configuration instead of code generation.

[Unreleased]: https://github.com/3scale/apicast/compare/v3.6.0...HEAD
[2.0.0]: https://github.com/3scale/apicast/compare/v0.2...v2.0.0
[3.0.0-alpha1]: https://github.com/3scale/apicast/compare/v2.0.0...v3.0.0-alpha1
[3.0.0-alpha2]: https://github.com/3scale/apicast/compare/v3.0.0-alpha1...v3.0.0-alpha2
[3.0.0-beta1]: https://github.com/3scale/apicast/compare/v3.0.0-alpha2...v3.0.0-beta1
[3.0.0-beta2]: https://github.com/3scale/apicast/compare/v3.0.0-beta1...v3.0.0-beta2
[3.0.0-beta3]: https://github.com/3scale/apicast/compare/v3.0.0-beta2...v3.0.0-beta3
[3.0.0]: https://github.com/3scale/apicast/compare/v3.0.0-beta3...v3.0.0
[3.1.0-alpha1]: https://github.com/3scale/apicast/compare/v3.0.0...v3.1.0-alpha1
[3.1.0-beta1]: https://github.com/3scale/apicast/compare/v3.1.0-alpha1...v3.1.0-beta1
[3.1.0-beta2]: https://github.com/3scale/apicast/compare/v3.1.0-beta1...v3.1.0-beta2
[3.1.0-rc1]: https://github.com/3scale/apicast/compare/v3.1.0-beta2...v3.1.0-rc1
[3.1.0-rc2]: https://github.com/3scale/apicast/compare/v3.1.0-rc1...v3.1.0-rc2
[3.1.0]: https://github.com/3scale/apicast/compare/v3.1.0-rc2...v3.1.0
[3.2.0-alpha1]: https://github.com/3scale/apicast/compare/v3.1.0...v3.2.0-alpha1
[3.2.0-alpha2]: https://github.com/3scale/apicast/compare/v3.2.0-alpha1...v3.2.0-alpha2
[3.2.0-beta1]: https://github.com/3scale/apicast/compare/v3.2.0-alpha2...v3.2.0-beta1
[3.2.0-beta2]: https://github.com/3scale/apicast/compare/v3.2.0-beta1...v3.2.0-beta2
[3.2.0-beta3]: https://github.com/3scale/apicast/compare/v3.2.0-beta2...v3.2.0-beta3
[3.2.0-rc1]: https://github.com/3scale/apicast/compare/v3.2.0-beta3...v3.2.0-rc1
[3.2.0-rc2]: https://github.com/3scale/apicast/compare/v3.2.0-rc1...v3.2.0-rc2
[3.2.0]: https://github.com/3scale/apicast/compare/v3.2.0-rc2...v3.2.0
[3.2.1]: https://github.com/3scale/apicast/compare/v3.2.0...v3.2.1
[3.3.0-beta1]: https://github.com/3scale/apicast/compare/v3.2.1...v3.3.0-beta1
[3.3.0-beta2]: https://github.com/3scale/apicast/compare/v3.3.0-beta1...v3.3.0-beta2
[3.3.0-cr1]: https://github.com/3scale/apicast/compare/v3.3.0-beta2...v3.3.0-cr1
[3.3.0-cr2]: https://github.com/3scale/apicast/compare/v3.3.0-cr1...v3.3.0-cr2
[3.3.0]: https://github.com/3scale/apicast/compare/v3.3.0-cr2...v3.3.0
[3.4.0-beta1]: https://github.com/3scale/apicast/compare/v3.3.0...v3.4.0-beta1
[3.4.0-rc1]: https://github.com/3scale/apicast/compare/v3.4.0-beta1...v3.4.0-rc1
[3.4.0-rc2]: https://github.com/3scale/apicast/compare/v3.4.0-rc1...v3.4.0-rc2
[3.4.0]: https://github.com/3scale/apicast/compare/v3.4.0-rc2...v3.4.0
[3.5.0-beta1]: https://github.com/3scale/apicast/compare/v3.4.0...v3.5.0-beta1
[3.5.0-rc1]: https://github.com/3scale/apicast/compare/v3.5.0-beta1...v3.5.0-rc1
[3.5.0]: https://github.com/3scale/apicast/compare/v3.5.0-beta1...v3.5.0
[3.5.1]: https://github.com/3scale/apicast/compare/v3.5.0...v3.5.1
[3.6.0-beta1]: https://github.com/3scale/apicast/compare/v3.5.1...v3.6.0-beta1
[3.6.0-rc1]: https://github.com/3scale/apicast/compare/v3.6.0-beta1...v3.6.0-rc1
[3.6.0-rc2]: https://github.com/3scale/apicast/compare/v3.6.0-rc1...v3.6.0-rc2
[3.6.0]: https://github.com/3scale/apicast/compare/v3.6.0-rc2...v3.6.0
