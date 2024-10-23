--!strict
local sha256 = require('./init')

local newSha256 = sha256.new(true, true)
newSha256:update'Message to hash'
-- newSha256:update('key');
-- newSha256:array()

print(newSha256)