--!strict
local sha256 = require('./init')

local n = sha256.new():update('The quick brown fox jumps over the lazy dog') :: sha256.Sha256
print(n:hex())