--!strict
type Sha256Impl = {
    __index: Sha256Impl,
    new: (is224: boolean?, sharedMemory: boolean?) -> Sha256,
    update: (self: Sha256, message: string | { [any]: any }) -> Sha256?,
    hash: (self: Sha256) -> (),
    finalize: (self: Sha256) -> (),
    array: (self: Sha256) -> { [number]: number },
    hex: (self: Sha256) -> string
}

export type Sha256 = typeof(setmetatable({} :: {
    blocks: { [number]: number },
    h0: number,
    h1: number,
    h2: number,
    h3: number,
    h4: number,
    h5: number,
    h6: number,
    h7: number,
    block: number,
    start: number,
    bytes: number,
    hBytes: number,
    finalized: boolean,
    hashed: boolean,
    first: boolean,
    is224: boolean?,
    lastByteIndex: number?,
}, {} :: Sha256Impl))

local shift = { [0] = 24, 16, 8, 0 }
local extra = { [0] = -2147483648, 8388608, 32768, 128 }
local hexChars = { [0]='0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' }
local k = {
    [0] = 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
} 

local bor = bit32.bor
local band = bit32.band
local bnot = bit32.bnot
local lshift = bit32.lshift
local rshift = bit32.rshift
local arshift = bit32.arshift


local sha256 = {} :: Sha256Impl
sha256.__index = sha256

function sha256.new(is224, sharedMemory)
    local self = {}
    local blocks = {}

    if sharedMemory then
        for i=0, 16 do
            blocks[i] = 0
            self.blocks = blocks
        end 
    else 
        self.blocks = { [0]=0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
    end

    if is224 then
        self.h0 = 0xc1059ed8
        self.h1 = 0x367cd507
        self.h2 = 0x3070dd17
        self.h3 = 0xf70e5939
        self.h4 = 0xffc00b31
        self.h5 = 0x68581511
        self.h6 = 0x64f98fa7
        self.h7 = 0xbefa4fa4
    else 
        self.h0 = 0x6a09e667
        self.h1 = 0xbb67ae85
        self.h2 = 0x3c6ef372
        self.h3 = 0xa54ff53a
        self.h4 = 0x510e527f
        self.h5 = 0x9b05688c
        self.h6 = 0x1f83d9ab
        self.h7 = 0x5be0cd19
    end

    self.block = 0
    self.start = 0
    self.bytes = 0
    self.hBytes = 0
    self.finalized = false
    self.hashed = false
    self.first = true
    self.is224 = is224

    return setmetatable(self, sha256)
end

function sha256.update(self, message)
    if self.finalized then 
        return
    end

    local code, i
    local index = 0
    local length = #message
    local blocks = self.blocks

    while index < length do
        if self.hashed then
            self.hashed = false
            blocks[0] = self.block
            self.block = 0
            for j=1, 16 do 
                blocks[j] = 0 
            end
        end

        if typeof(message) ~= 'string' then
            i = self.start+1
            while index < length and i < 64 do
                blocks[rshift(i, 2)] = bor(blocks[rshift(i, 2)], lshift(message[index], shift[band(i, 3)]))
                i+=1
                index+=1
            end
        else
            i = self.start
            while index < length and i < 64 do
                code = message:byte(index+1)
                if code < 0x80 then
                    blocks[rshift(i, 2)] = lshift(code, shift[band(i, 3)])
                    i+=1
                elseif code < 0x800 then
                    blocks[rshift(i, 2)] = bor(blocks[rshift(i, 2)], lshift( bor(0xc0, rshift(code, 6)), shift[band(i, 3)]))
                    i+=1
                    blocks[rshift(i, 2)] = bor(blocks[rshift(i, 2)], lshift( bor(0x80, band(code, 0x3f)), shift[band(i, 3)]))
                    i+=1
                elseif code < 0xd800 or code >= 0xe000 then
                    blocks[rshift(i, 2)] = bor(blocks[rshift(i, 2)], lshift( bor(0xe0, rshift(code, 12)), shift[band(i, 3)]))
                    i+=1
                    blocks[rshift(i, 2)] = bor(blocks[rshift(i, 2)], lshift(bor(0x80, band(rshift(code, 6), 0x3f)), shift[band(i, 3)]))
                    i+=1
                    blocks[rshift(i, 2)] = bor(blocks[rshift(i, 2)], lshift( bor(0x80, band(code, 0x3f)), shift[band(i, 3)]))
                    i+=1
                else
                    code = 0x10000 + bor(lshift(band(code, 0x3ff), 10), band( message:byte(index+1), 0x3ff))
                    i+=1
                    blocks[rshift(i, 2)] = bor(blocks[rshift(i, 2)], lshift( bor(0xf0, rshift(code, 18)), shift[band(i, 3)]))
                    i+=1
                    blocks[rshift(i, 2)] = bor(blocks[rshift(i, 2)], lshift(bor(0x80, band(rshift(code, 12), 0x3f)), shift[band(i, 3)]))
                    i+=1
                    blocks[rshift(i, 2)] = bor(blocks[rshift(i, 2)], lshift(bor(0x80, band(rshift(code, 6), 0x3f)), shift[band(i, 3)]))
                    i+=1
                    blocks[rshift(i, 2)] = bor(blocks[rshift(i, 2)], lshift( bor(0x80, band(code, 0x3f)), shift[band(i, 3)]))
                    i+=1
                end
                index+=1
            end
        end

        self.lastByteIndex = i
        self.bytes += i - self.start
    
        if i >= 64 then
            self.block = blocks[16]
            self.start = i - 64
            self:hash()
            self.hashed = true
        else
            self.start = i
        end
    end

    if self.bytes > 4294967295 then
        self.hBytes += self.bytes / lshift(4294967296, 0)
        self.bytes = self.bytes % 4294967296
    end

    return self
end

function sha256.finalize(self)
    if self.finalized then
        return 
    end

    self.finalized = true
    local blocks = self.blocks
    local i = self.lastByteIndex :: number

    blocks[16] = self.block
    blocks[rshift(i, 2)] = bor(blocks[rshift(i, 2)], extra[band(i, 3)])
    self.block = blocks[16]

    if i >= 56 then
        if not self.hashed then
            self:hash()
        end
        blocks[0] = self.block
        for j=1, 16 do
            blocks[j] = 0
        end
    end

    blocks[14] = bor(lshift(self.hBytes, 3), rshift(self.bytes, 29))
    blocks[15] = lshift(self.bytes, 3)
    
    self:hash()
end

function sha256.hash(self)
    local a, b, c, d, e, f, g, h = self.h0, self.h1, self.h2, self.h3, self.h4, self.h5, self.h6, self.h7
    local blocks = self.blocks
    local j, s0, s1, maj, t1, t2, ch, ab, da, cd, bc

    j = 16
    while j < 64 do
        
        j+=1
    end

    j = 0
    while j < 64 do
        if self.first then
            if self.is224 then
                
            else
                
            end
            self.first = false
        else
        
        end
        
        j += 4
    end

    self.h0 = self.h0 + lshift(a, 0)
    self.h1 = self.h1 + lshift(b, 0)
    self.h2 = self.h2 + lshift(c, 0)
    self.h3 = self.h3 + lshift(d, 0)
    self.h4 = self.h4 + lshift(e, 0)
    self.h5 = self.h5 + lshift(f, 0)
    self.h6 = self.h6 + lshift(g, 0)
    self.h7 = self.h7 + lshift(h, 0)
end

function sha256.array(self)
    self:finalize()

    local h0 = self.h0
    local h1 = self.h1
    local h2 = self.h2
    local h3 = self.h3
    local h4 = self.h4
    local h5 = self.h5
    local h6 = self.h6
    local h7 = self.h7

    local arr = {
        band(rshift(h0, 24), 0xFF), band(rshift(h0, 16), 0xFF),
        band(rshift(h0, 8), 0xFF), band(h0, 0xFF),
        band(rshift(h1, 24), 0xFF), band(rshift(h1, 16), 0xFF),
        band(rshift(h1, 8), 0xFF), band(h1, 0xFF),
        band(rshift(h2, 24), 0xFF), band(rshift(h2, 16), 0xFF),
        band(rshift(h2, 8), 0xFF), band(h2, 0xFF),
        band(rshift(h3, 24), 0xFF), band(rshift(h3, 16), 0xFF),
        band(rshift(h3, 8), 0xFF), band(h3, 0xFF),
        band(rshift(h4, 24), 0xFF), band(rshift(h4, 16), 0xFF),
        band(rshift(h4, 8), 0xFF), band(h4, 0xFF),
        band(rshift(h5, 24), 0xFF), band(rshift(h5, 16), 0xFF),
        band(rshift(h5, 8), 0xFF), band(h5, 0xFF),
        band(rshift(h6, 24), 0xFF), band(rshift(h6, 16), 0xFF),
        band(rshift(h6, 8), 0xFF), band(h6, 0xFF),
    }

    if not self.is224 then
        table.insert(arr, band(rshift(h7, 24), 0xFF))
        table.insert(arr, band(rshift(h7, 16), 0xFF))
        table.insert(arr, band(rshift(h7, 8), 0xFF))
        table.insert(arr, band(h7, 0xFF))
    end

    return arr
end

function sha256.hex(self)
    self:finalize()
    local h0 = self.h0
    local h1 = self.h1
    local h2 = self.h2
    local h3 = self.h3
    local h4 = self.h4
    local h5 = self.h5
    local h6 = self.h6
    local h7 = self.h7
    
    local hex = ''
    hex ..= hexChars[band(rshift(h0, 28), 0x0F)]
    hex ..= hexChars[band(rshift(h0, 24), 0x0F)]
    hex ..= hexChars[band(rshift(h0, 20), 0x0F)]
    hex ..= hexChars[band(rshift(h0, 16), 0x0F)]
    hex ..= hexChars[band(rshift(h0, 12), 0x0F)]
    hex ..= hexChars[band(rshift(h0, 8), 0x0F)]
    hex ..= hexChars[band(rshift(h0, 4), 0x0F)]
    hex ..= hexChars[band(h0, 0x0F)]

    hex ..= hexChars[band(rshift(h1, 28), 0x0F)]
    hex ..= hexChars[band(rshift(h1, 24), 0x0F)]
    hex ..= hexChars[band(rshift(h1, 20), 0x0F)]
    hex ..= hexChars[band(rshift(h1, 16), 0x0F)]
    hex ..= hexChars[band(rshift(h1, 12), 0x0F)]
    hex ..= hexChars[band(rshift(h1, 8), 0x0F)]
    hex ..= hexChars[band(rshift(h1, 4), 0x0F)]
    hex ..= hexChars[band(h1, 0x0F)]

    hex ..= hexChars[band(rshift(h2, 28), 0x0F)]
    hex ..= hexChars[band(rshift(h2, 24), 0x0F)]
    hex ..= hexChars[band(rshift(h2, 20), 0x0F)]
    hex ..= hexChars[band(rshift(h2, 16), 0x0F)]
    hex ..= hexChars[band(rshift(h2, 12), 0x0F)]
    hex ..= hexChars[band(rshift(h2, 8), 0x0F)]
    hex ..= hexChars[band(rshift(h2, 4), 0x0F)]
    hex ..= hexChars[band(h2, 0x0F)]

    hex ..= hexChars[band(rshift(h3, 28), 0x0F)]
    hex ..= hexChars[band(rshift(h3, 24), 0x0F)]
    hex ..= hexChars[band(rshift(h3, 20), 0x0F)]
    hex ..= hexChars[band(rshift(h3, 16), 0x0F)]
    hex ..= hexChars[band(rshift(h3, 12), 0x0F)]
    hex ..= hexChars[band(rshift(h3, 8), 0x0F)]
    hex ..= hexChars[band(rshift(h3, 4), 0x0F)]
    hex ..= hexChars[band(h3, 0x0F)]

    hex ..= hexChars[band(rshift(h4, 28), 0x0F)]
    hex ..= hexChars[band(rshift(h4, 24), 0x0F)]
    hex ..= hexChars[band(rshift(h4, 20), 0x0F)]
    hex ..= hexChars[band(rshift(h4, 16), 0x0F)]
    hex ..= hexChars[band(rshift(h4, 12), 0x0F)]
    hex ..= hexChars[band(rshift(h4, 8), 0x0F)]
    hex ..= hexChars[band(rshift(h4, 4), 0x0F)]
    hex ..= hexChars[band(h4, 0x0F)]

    hex ..= hexChars[band(rshift(h5, 28), 0x0F)]
    hex ..= hexChars[band(rshift(h5, 24), 0x0F)]
    hex ..= hexChars[band(rshift(h5, 20), 0x0F)]
    hex ..= hexChars[band(rshift(h5, 16), 0x0F)]
    hex ..= hexChars[band(rshift(h5, 12), 0x0F)]
    hex ..= hexChars[band(rshift(h5, 8), 0x0F)]
    hex ..= hexChars[band(rshift(h5, 4), 0x0F)]
    hex ..= hexChars[band(h5, 0x0F)]

    hex ..= hexChars[band(rshift(h6, 28), 0x0F)]
    hex ..= hexChars[band(rshift(h6, 24), 0x0F)]
    hex ..= hexChars[band(rshift(h6, 20), 0x0F)]
    hex ..= hexChars[band(rshift(h6, 16), 0x0F)]
    hex ..= hexChars[band(rshift(h6, 12), 0x0F)]
    hex ..= hexChars[band(rshift(h6, 8), 0x0F)]
    hex ..= hexChars[band(rshift(h6, 4), 0x0F)]
    hex ..= hexChars[band(h6, 0x0F)]

    if not self.is224 then
        hex ..= hexChars[band(rshift(h7, 28), 0x0F)]
        hex ..= hexChars[band(rshift(h7, 24), 0x0F)]
        hex ..= hexChars[band(rshift(h7, 20), 0x0F)]
        hex ..= hexChars[band(rshift(h7, 16), 0x0F)]
        hex ..= hexChars[band(rshift(h7, 12), 0x0F)]
        hex ..= hexChars[band(rshift(h7, 8), 0x0F)]
        hex ..= hexChars[band(rshift(h7, 4), 0x0F)]
        hex ..= hexChars[band(h7, 0x0F)]
    end

    return hex
end

return sha256