local _M = require('apicast.policy.standalone.configuration')

describe('Standalone Configuration', function()
    describe('.new', function()
        it('accepts file url', function()
            assert(_M.new('file://tmp/conf.toml'))
        end)

        it('does not accept http', function()
            assert.returns_error('scheme not supported', _M.new('http://example.com'))
        end)

        it('does not accept https', function()
            assert.returns_error('scheme not supported', _M.new('https://example.com'))
        end)

        it('does not accept invalid URL', function()
            assert.returns_error('missing scheme', _M.new('invalid url'))
        end)
    end)

    describe('.load', function()
        local function load(file)
            return _M.new(('file://spec/fixtures/standalone/%s'):format(file)):load()
        end

        it('loads valid .yml file', function()
            assert.same({ global = ngx.null }, load('valid.yml'))
        end)

        it('loads valid .json file', function()
            assert.same({ global = {} }, load('valid.json'))
        end)

        it('not loads invalid .yml file', function()
            assert.returns_error('2:5: did not find expected \'-\' indicator', load('invalid.yml'))
        end)

        it('not loads invalid .json file', function()
            assert.returns_error('Expected value but found invalid number at character 1', load('invalid.json'))
        end)

        it('not loads invalid .txt file', function()
            assert.returns_error('unsupported format', load('invalid.txt'))
        end)
    end)
end)
