local TemplateString = require 'apicast.template_string'
local ngx_variable = require 'apicast.policy.ngx_variable'
local LinkedList = require('apicast.linked_list')

describe('template string', function()
  before_each(function()
    -- Stub the available context to avoid depending on ngx.var.*
    stub(ngx_variable, 'available_context', function(context) return context end)
  end)

  it('evaluates to empty string when an invalid liquid is provided', function()
    local template_ex1 = TemplateString.new('{{ abc ', 'liquid')
    assert.equals('', template_ex1:render({}))

    local template_ex2 = TemplateString.new('abc }}', 'liquid')
    assert.equals('', template_ex2:render({}))

    local template_ex3 = TemplateString.new('{{ now() }}', 'liquid')
    assert.equals('', template_ex3:render({}))
  end)

  it('renders plain text', function()
    local plain_text_template = TemplateString.new('{{ a_key }}', 'plain')
    assert.equals('{{ a_key }}', plain_text_template:render())
  end)

  it('renders liquid', function()
    local liquid_template = TemplateString.new('{{ a_key }}', 'liquid')
    assert.equals('a_value', liquid_template:render({ a_key = 'a_value' }))
  end)

  it('when rendering liquid, it can use the vars exposed in ngx_variable', function()
    stub(ngx_variable, 'available_context', function(policies_context)
      local exposed = { a_key_exposed_in_ngx_var = 'a_value' }
      return LinkedList.readonly(exposed, policies_context)
    end)

    local liquid_template = TemplateString.new('{{ a_key_exposed_in_ngx_var }}', 'liquid')
    assert.equals('a_value', liquid_template:render({}))
  end)

  it('can apply liquid filters', function()
    local liquid_template = TemplateString.new('{{ "something" | md5 }}', 'liquid')
    assert.equals(ngx.md5('something'), liquid_template:render({}))
  end)

  describe(':render', function()
    it('it allows context to be garbage collected #gc', function()
      local template =  TemplateString.new('string', 'liquid')
      local context = { 'value' }

      template:render(context)

      -- store the object so we can verify it was GC'd later
      local gc = setmetatable({ context = context }, { __mode = 'vk' })
      -- luassert stub takes a reference to parameters passed through
      ngx_variable.available_context:revert()
      context = nil

      collectgarbage()
      assert.is_nil(gc.context)
    end)

    it('does not parse the document twice', function()
      local template = TemplateString.new('string', 'liquid')

      stub(require('liquid').Parser, 'document', function()
        error('this should not be called')
      end)

      assert.same('string', template:render({}))
      assert.same('string', template:render({}))
    end)
  end)

  describe('.new', function()
    it('returns nil and an error with invalid type', function()
      local template, err = TemplateString.new('some_string', 'invalid_type')
      assert.is_nil(template)
      assert.is_not_nil(err)
    end)
  end)
end)
