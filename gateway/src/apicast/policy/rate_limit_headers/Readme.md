# Rate limits headers

This policy send the headers back to the user with the rate limit information.
This policy implements the [RateLimit Header Fields for HTTP draft]
(https://ioggstream.github.io/draft-polli-ratelimit-headers/draft-polli-ratelimit-headers.html)


## Headers accuracy:

This header information is retrieved from
[APISonator](https://github.com/3scale/apisonator), but is not always sync, on
second request we cached the information, so it's possible that the information
is not 100% accurate with APISonator, but APIcast always try to sync with
backend.

The main reason for this is performance, in this case, call to APISonator in
request time is time-consuming, and it's not needed at all.

If data accurate is needed, caching can be disabled, so data will always be 100%
accurate.
