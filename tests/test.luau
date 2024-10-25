--!strict
local sha256 = require('../init')

local n = sha256.new(false, true):update('test') :: sha256.Sha256
print(n:hex())