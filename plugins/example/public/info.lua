---@diagnostic disable: undefined-global
---@type fun(data: table)
RegisterPlugin = registerPlugin
---@type fun(name: string,func: function)
RegisterFunction = registerFunction

-- This code will automatically adjust based on the values in package.json, no modification needed.
RegisterPlugin({
    name = "react-project-init",
    description = "A CHM Plugin template with Vite, React,Tailwind CSS, shadcn/ui, and ESLint.",
    version = "0.0.0",
    uiConfig = {
        mainFile = "",
        cssFile = "",
        exportName = "./App"
    }
})

-- Register a function that can be called from the UI
-- this plugin scope+name ==> function
-- syntax: <backendURL>/<plugin-name>/<function-name>

-- http://localhost:8080/api/plugin/example-plugin/add
RegisterFunction("add", function(data)
    -- if json data is Object like {"a":1,"b":2}
    local a, b = data.a, data.b
    -- return a + b
    -- if json data is Array like [1,2]
    -- local a, b = data.value[1], data.value[2]
    return a + b
end)

-- http://localhost:8080/api/plugin/example-plugin/sub
RegisterFunction("sub", function(data)
    -- if json data is Object like {"a":1,"b":2}
    local a, b = data.a, data.b
    -- return a + b
    -- if json data is Array like [1,2]
    -- local a, b = data.value[1], data.value[2]
    return a - b
end)
