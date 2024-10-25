--!strict
local sha256 = require '../init'

local n = sha256.new():update('this luau sha256')
print(n:hex())