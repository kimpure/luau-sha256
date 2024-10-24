local function replace_shift_operations(expression)
    expression = string.gsub(expression, "(%w+)%s*>>>%s*(%d+)", "rshift(%1, %2)")
    
    expression = string.gsub(expression, "(%w+)%s*<<%s*(%d+)", "lshift(%1, %2)")
    
    return expression
end

local expression = "((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);"
local result = replace_shift_operations(expression)
print(result)
