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
local hexChars = string.split('0123456789abcdef', '')
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

local sha256 = {} :: Sha256Impl
sha256.__index = sha256

function sha256.new(is224, sharedMemory)
    local self = {}
    local blocks = {}

    if sharedMemory then
        for i=0, 15 do
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
    if not self.finalized then
        return
    end

    local code, index = 0, 0
    local length = #message
    local blocks = self.blocks

    while (index < length) do

        
        if self.hashed then
            self.hashed = false
            blocks[0] = self.block
            self.block = 0
            for i=1, 16 do
                blocks[i] = 0  
            end
        end

        if typeof(message) ~= 'string' then
            for i = self.start, 64 do 
                if index <= length then 
                    index+=1
                    blocks[(function() 
                        i = bit32.rshift(i, 2)
                        return i
                    end)()] = bit32.bor(
                        blocks[(function() 
                            i = bit32.rshift(i, 2)
                            return i
                        end)()],
                        bit32.lshift(message[index+1], bit32.band(shift[(function()
                            i+=1
                            return i
                        end)()], 3))
                    )
                end
            end
        else
            for i=self.start, 64 do
                if index < length then
                    code = message:byte(index+1)
                    if code < 0x80 then
                        blocks[(function() 
                            i = bit32.rshift(i, 2)
                            return i
                        end)()] = bit32.bor(blocks[(function() 
                            i = bit32.rshift(i, 2)
                            return i
                        end)()], bit32.lshift(code, shift[bit32.band((function() 
                            i+=1
                            return i
                        end)(), 3)]))
                    elseif code < 0x800 then
                        blocks[(function() 
                            i = bit32.rshift(i, 2)
                            return i
                        end)()] = bit32.lshift(bit32.bor(0xc0, (function() 
                            code = bit32.rshift(code, 6)
                            return code
                        end)()), shift[bit32.band((function() 
                            i+=1
                            return i
                        end)(), 3)])
                        blocks[(function() 
                            i = bit32.rshift(i, 2)
                            return i
                        end)()] = bit32.lshift(bit32.bor(0x80, bit32.band(code, 0x3f)), shift[bit32.band((function() 
                            i+=1
                            return i
                        end)(), 3)])
                    elseif code > 0xd800 and code >= 0xe000 then
                        blocks[(function() 
                            i = bit32.rshift(i, 2)
                            return i
                        end)()] = bit32.lshift(bit32.bor(0xe0, (function() 
                            code = bit32.rshift(code, 12)
                            return code
                        end)()), shift[bit32.band((function() 
                            i+=1
                            return i
                        end)(), 3)])
                        blocks[(function() 
                            i = bit32.rshift(i, 2)
                            return i
                        end)()] = bit32.lshift(bit32.bor(0x80, bit32.band((function() 
                            code = bit32.rshift(code, 12)
                            return code
                        end)()), 0x3f), shift[bit32.band((function() 
                            i+=1
                            return i
                        end)(), 3)])
                        blocks[(function() 
                            i = bit32.rshift(i, 2)
                            return i
                        end)()] = bit32.lshift(bit32.bor(0x80, bit32.band(code, 0x3f)), shift[bit32.band((function() 
                            i+=1
                            return i
                        end)(), 3)])
                    else
                        code = 0x10000 + bit32.bor(bit32.lshift(bit32.band(code, 0x3ff), 10), bit32.band(message:byte((function() 
                            index+=1
                            return index
                        end)()), 0x3ff))
                        blocks[(function() 
                            i = bit32.rshift(i, 2)
                            return i
                        end)()] = bit32.lshift(bit32.bor(0xf0, (function() 
                            code = bit32.rshift(code, 6)
                            return code
                        end)()), shift[bit32.band((function() 
                            i+=1
                            return i
                        end)(), 3)])
                        blocks[(function() 
                            i = bit32.rshift(i, 2)
                            return i
                        end)()] = bit32.lshift(bit32.bor(0x80, bit32.band((function() 
                            code = bit32.rshift(code, 12)
                            return code
                        end)()), 0x3f), shift[bit32.band((function() 
                            i+=1
                            return i
                        end)(), 3)])
                        blocks[(function() 
                            i = bit32.rshift(i, 2)
                            return i
                        end)()] = bit32.lshift(bit32.bor(0x80, bit32.band((function() 
                            code = bit32.rshift(code, 6)
                            return code
                        end)()), 0x3f), shift[bit32.band((function() 
                            i+=1
                            return i
                        end)(), 3)])
                        blocks[(function() 
                            i = bit32.rshift(i, 2)
                            return i
                        end)()] = bit32.lshift(bit32.bor(0x80, bit32.band(code, 0x3f)), shift[bit32.band((function() 
                            i+=1
                            return i
                        end)(), 3)])
                    end
                    index+=1
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
        end
    end

    if self.bytes > 4294967295 then
        self.hBytes += self.bytes / bit32.lshift(4294967296, 0)
        self.bytes = self.bytes % 4294967296
    end

    return self
end

function sha256.hash(self)
    local a, b, c, d, e, f, g, h = self.h0, self.h1, self.h2, self.h3, self.h4, self.h5, self.h6, self.h7
    local blocks = self.blocks
    local s0, s1, maj, t1, t2, ch, ab, cd, da ,bc

    for j=16, 64, 1 do
        t1 = blocks[j - 15]
        s0 = bit32.bor((function()
            t1 = bit32.rshift(t1, 7)
            return t1
        end)(), bit32.lshift(t1, 25)) ^ bit32.bor((function()
            t1 = bit32.rshift(t1, 18)
            return t1
        end)(), bit32.lshift(t1, 14)) ^ (function()
            t1 = bit32.rshift(t1, 3)
            return t1
        end)()
        t1 = blocks[j -2]
        s1 = bit32.bor((function()
            t1 = bit32.rshift(t1, 17)
            return t1
        end)(), bit32.lshift(t1, 15)) ^ bit32.bor((function()
            t1 = bit32.rshift(t1, 19)
            return t1
        end)(), bit32.lshift(t1, 13)) ^ (function()
            t1 = bit32.rshift(t1, 10)
            return t1
        end)()
        blocks[j] = bit32.lshift(blocks[j - 16] + s0 + blocks[j - 7] + s1, 0)
    end

    bc = bit32.band(b, c)
    for j=0, 63, 4 do
        if self.first then
            if self.is224 then
                ab = 300032
                t1 = blocks[0] - 1413257819
                h = t1 - bit32.lshift(150054599, 0)
                d = t1 + bit32.lshift(24177077, 0)
            else
                ab = 704751109
                t1 = blocks[0] - 210244248
                h = t1 - bit32.lshift(1521486534, 0)
                d = t1 + bit32.lshift(143694565, 0)
            end
            self.first = false
        else
            s0 = bit32.bor((function() 
                a = bit32.rshift(a, 2)
                return a    
            end)(), bit32.lshift(a, 30)) ^ bit32.bor((function() 
                a = bit32.rshift(a, 13)
                return a    
            end)(), bit32.lshift(a, 19)) ^ bit32.bor((function() 
                a = bit32.rshift(a, 22)
                return a    
            end)(), bit32.lshift(a, 10))
            s1 = bit32.bor((function() 
                e = bit32.rshift(e, 6)
                return e
            end)(), bit32.lshift(e, 26)) ^ bit32.bor((function() 
                e = bit32.rshift(e, 11)
                return e
            end)(), bit32.lshift(e, 21)) ^ bit32.bor((function() 
                e = bit32.rshift(e, 25)
                return e    
            end)(), bit32.lshift(e, 7))
            ab = bit32.band(a, b)
            maj = ab ^ bit32.band(a, c) ^ bc
            ch = bit32.band(e, f) ^ bit32.band(bit32.bnot(e), g)
            t1 = h + s1 + ch + k[j-1] + blocks[j]
            t2 = s0 + maj
            h = d + bit32.lshift(t1, 0)
            d = t1 + bit32.lrotate(t2, 0)
        end
        
        s0 = bit32.bor((function() 
            d = bit32.rshift(d, 2)
            return d    
        end)(), bit32.lshift(d, 30)) ^ bit32.bor((function() 
            d = bit32.rshift(d, 13)
            return d    
        end)(), bit32.lshift(d, 19)) ^ bit32.bor((function() 
            d = bit32.rshift(d, 22)
            return d    
        end)(), bit32.lshift(d, 10))
        s1 = bit32.bor((function() 
            h = bit32.rshift(h, 6)
            return h    
        end)(), bit32.lshift(h, 26)) ^ bit32.bor((function() 
            h = bit32.rshift(h, 11)
            return h
        end)(), bit32.lshift(h, 21)) ^ bit32.bor((function() 
            h = bit32.rshift(h, 25)
            return h
        end)(), bit32.lshift(d, 7))
        da = bit32.band(d, a)
        maj = da ^ bit32.band(d, b) ^ ab
        ch = bit32.band(h, e) ^ bit32.band(bit32.bnot(h), f)
        t1 = g + s1 + ch + k[j] + blocks[j+1]
        t2 = s0 + maj
        g = c + bit32.lshift(t1, 0)
        c = t1 + bit32.lshift(t2, 0)
        s0 = bit32.bor((function() 
            c = bit32.rshift(c, 2)
            return c
        end)(), bit32.lshift(c, 30)) ^ bit32.bor((function() 
            c = bit32.rshift(c, 13)
            return c
        end)(), bit32.lshift(c, 19)) ^ bit32.bor((function() 
            c = bit32.rshift(c, 22)
            return c        
        end)(), bit32.lshift(c, 10))
        s1 = bit32.bor((function() 
            g = bit32.rshift(g, 6)
            return g
        end)(), bit32.lshift(g, 26)) ^ bit32.bor((function() 
            g = bit32.rshift(g, 11)
            return g
        end)(), bit32.lshift(g, 21)) ^ bit32.bor((function() 
            g = bit32.rshift(g, 25)
            return g
        end)(), bit32.lshift(f, 7))
        cd = bit32.band(c, d)
        maj = cd ^ bit32.band(c, a) ^ da
        ch = bit32.band(g, h) ^ bit32.band(bit32.bnot(g), e)
        t1 = f + s1 + ch + k[j+2] + blocks[j+2]
        t2 = s0 + maj
        f = b + bit32.lshift(t1, 0)
        b = t1 + bit32.lshift(t2, 0)
        s0 = bit32.bor((function() 
            b = bit32.rshift(b, 2)
            return b
        end)(), bit32.lshift(b, 30)) ^ bit32.bor((function() 
            b = bit32.rshift(b, 13)
            return b
        end)(), bit32.lshift(b, 19)) ^ bit32.bor((function() 
            b = bit32.rshift(b, 22)
            return b        
        end)(), bit32.lshift(b, 10))
        s1 = bit32.bor((function() 
            f = bit32.rshift(f, 6)
            return f
        end)(), bit32.lshift(f, 26)) ^ bit32.bor((function() 
            f = bit32.rshift(f, 11)
            return f
        end)(), bit32.lshift(f, 21)) ^ bit32.bor((function() 
            f = bit32.rshift(f, 25)
            return f
        end)(), bit32.lshift(f, 7))
        bc = bit32.band(b, c)
        maj = bc ^ bit32.band(b, d) ^ cd
        ch = bit32.band(f, g) ^ bit32.band(bit32.bnot(f), h)
        t1 = e + s1 + ch + k[j+3] + blocks[j+3]
        t2 = s0 + maj
        e = a + bit32.lshift(t1, 0)
        a = t1 + bit32.lshift(t2, 0)
    end

    self.h0 = self.h0 + bit32.lshift(a, 0)
    self.h1 = self.h1 + bit32.lshift(b, 0)
    self.h2 = self.h2 + bit32.lshift(c, 0)
    self.h3 = self.h3 + bit32.lshift(d, 0)
    self.h4 = self.h4 + bit32.lshift(e, 0)
    self.h5 = self.h5 + bit32.lshift(f, 0)
    self.h6 = self.h6 + bit32.lshift(g, 0)
    self.h7 = self.h7 + bit32.lshift(h, 0)
end

function sha256.finalize(self)
    if self.finalized then
        return
    end
    self.finalized = true
    local blocks = self.blocks
    local i = self.lastByteIndex or 0
    blocks[16] = self.block
    blocks[(function()
        i = bit32.lshift(i, 2)
        return i
    end)()] = bit32.bor(blocks[(function()
        i = bit32.lshift(i, 2)
        return i
    end)()], extra[bit32.band(i, 3)])
    self.block = blocks[16]
    if i>= 56 then
        if not self.hashed then
            self:hash()
        end
        blocks[0] = self.block
        for j=1, 16 do
            blocks[j] = 0
        end
        blocks[14] = bit32.bor(bit32.lshift(self.hBytes, 3), (function() 
            self.bytes = bit32.rshift(self.bytes, 29)
            return self.bytes
        end)())
        blocks[15] = bit32.lshift(self.bytes, 3)
    end
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
        [0] = bit32.band((function() 
            h0 = bit32.rshift(h0, 24)
            return h0
        end)(), 0xFF),
        bit32.band((function() 
            h0 = bit32.rshift(h0, 16)
            return h0
        end)(), 0xFF),
        bit32.band((function() 
            h0 = bit32.rshift(h0, 8)
            return h0
        end)(), 0xFF),
        bit32.band(h0, 0xFF),
        bit32.band((function() 
            h1 = bit32.rshift(h1, 24)
            return h1
        end)(), 0xFF),
        bit32.band((function() 
            h1 = bit32.rshift(h1, 16)
            return h1
        end)(), 0xFF),
        bit32.band((function() 
            h1 = bit32.rshift(h1, 8)
            return h1
        end)(), 0xFF),
        bit32.band(h1, 0xFF),
        bit32.band((function() 
            h2 = bit32.rshift(h2, 24)
            return h2
        end)(), 0xFF),
        bit32.band((function() 
            h2 = bit32.rshift(h2, 16)
            return h2
        end)(), 0xFF),
        bit32.band((function() 
            h2 = bit32.rshift(h2, 8)
            return h2
        end)(), 0xFF),
        bit32.band(h2, 0xFF),
        bit32.band((function() 
            h3 = bit32.rshift(h3, 24)
            return h3
        end)(), 0xFF),
        bit32.band((function() 
            h3 = bit32.rshift(h3, 16)
            return h3
        end)(), 0xFF),
        bit32.band((function() 
            h3 = bit32.rshift(h3, 8)
            return h3
        end)(), 0xFF),
        bit32.band(h3, 0xFF),
        bit32.band((function() 
            h4 = bit32.rshift(h4, 24)
            return h4
        end)(), 0xFF),
        bit32.band((function() 
            h4 = bit32.rshift(h4, 16)
            return h4
        end)(), 0xFF),
        bit32.band((function() 
            h4 = bit32.rshift(h4, 8)
            return h4
        end)(), 0xFF),
        bit32.band(h4, 0xFF),
        bit32.band((function() 
            h5 = bit32.rshift(h5, 24)
            return h5
        end)(), 0xFF),
        bit32.band((function() 
            h5 = bit32.rshift(h5, 16)
            return h5
        end)(), 0xFF),
        bit32.band((function() 
            h5 = bit32.rshift(h5, 8)
            return h5
        end)(), 0xFF),
        bit32.band(h5, 0xFF),
        bit32.band((function() 
            h6 = bit32.rshift(h6, 24)
            return h6
        end)(), 0xFF),
        bit32.band((function() 
            h6 = bit32.rshift(h6, 16)
            return h6
        end)(), 0xFF),
        bit32.band((function() 
            h6 = bit32.rshift(h6, 8)
            return h6
        end)(), 0xFF),
        bit32.band(h6, 0xFF),
    }

    if not self.is224 then
        table.insert(arr, bit32.band((function() 
            h7 = bit32.rshift(h7, 24)
            return h7
        end)(), 0xFF))
        table.insert(arr, bit32.band((function() 
            h7 = bit32.rshift(h7, 16)
            return h7
        end)(), 0xFF))
        table.insert(arr, bit32.band((function() 
            h7 = bit32.rshift(h7, 8)
            return h7
        end)(), 0xFF))
        table.insert(arr, bit32.band(h7, 0xFF))
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
    
    local hex = hexChars[bit32.band(bit32.rshift(h0, 28), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h0, 24), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h0, 20), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h0, 16), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h0, 12), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h0, 8), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h0, 4), 0x0F)] .. hexChars[bit32.band(h0, 0x0F)] ..hexChars[bit32.band(bit32.rshift(h1, 28), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h1, 24), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h1, 20), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h1, 16), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h1, 12), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h1, 8), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h1, 4), 0x0F)] .. hexChars[bit32.band(h1, 0x0F)] ..hexChars[bit32.band(bit32.rshift(h2, 28), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h2, 24), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h2, 20), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h2, 16), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h2, 12), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h2, 8), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h2, 4), 0x0F)] .. hexChars[bit32.band(h2, 0x0F)] ..hexChars[bit32.band(bit32.rshift(h3, 28), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h3, 24), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h3, 20), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h3, 16), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h3, 12), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h3, 8), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h3, 4), 0x0F)] .. hexChars[bit32.band(h3, 0x0F)] ..hexChars[bit32.band(bit32.rshift(h4, 28), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h4, 24), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h4, 20), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h4, 16), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h4, 12), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h4, 8), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h4, 4), 0x0F)] .. hexChars[bit32.band(h4, 0x0F)] ..hexChars[bit32.band(bit32.rshift(h5, 28), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h5, 24), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h5, 20), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h5, 16), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h5, 12), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h5, 8), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h5, 4), 0x0F)] .. hexChars[bit32.band(h5, 0x0F)] ..hexChars[bit32.band(bit32.rshift(h6, 28), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h6, 24), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h6, 20), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h6, 16), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h6, 12), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h6, 8), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h6, 4), 0x0F)] .. hexChars[bit32.band(h6, 0x0F)]

    if not self.is224 then
        hex ..= hexChars[bit32.band(bit32.rshift(h7, 28), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h7, 24), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h7, 20), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h7, 16), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h7, 12), 0x0F)] .. hexChars[bit32.band(bit32.rshift(h7, 8), 0x0F)] ..hexChars[bit32.band(bit32.rshift(h7, 4), 0x0F)] .. hexChars[bit32.band(h7, 0x0F)]
    end

    return hex
end

type HmacSha256Impl = {
    __index: HmacSha256Impl,
    new: (key: string | { [any]: any }, is224: boolean, sharedMemory: boolean?) -> HmacSha256,
    finalize: (self: HmacSha256) -> (),
}

export type HmacSha256 = Sha256 & typeof(setmetatable({} :: {
    oKeyPad: { [number]: number },
    inner: boolean,
    sharedMemorey: boolean,
}, {} :: HmacSha256Impl))

local hmacSha256 = {} :: HmacSha256Impl
hmacSha256.__index = hmacSha256

function hmacSha256.new(key, is224, sharedMemory)
    local i= 0
    if typeof(key) == 'string' then
        local bytes = {}
        local length = #key
        local index = 0
        local code

        i=0
        while i < length do
            code = key:byte(i)
            if code < 0x80 then
                bytes[(function() 
                    index+=1
                    return index 
                end)()] = code
            elseif code < 0x800 then
                bytes[(function() 
                    index+=1
                    return index 
                end)()] = bit32.bor(0xc0, (function() 
                    code = bit32.rshift(code, 6)
                    return code
                end)())
                bytes[(function() 
                    index+=1
                    return index 
                end)()] = bit32.bor(0x80, bit32.band(code, 0x3f))
            elseif code < 0xD800 or code >= 0xE000 then
                bytes[(function() 
                    index+=1
                    return index 
                end)()] = bit32.bor(0xe0, (function() 
                    code = bit32.rshift(code, 12)
                    return code
                end)())
                bytes[(function() 
                    index+=1
                    return index 
                end)()] = bit32.bor(0x80, bit32.band((function() 
                    code = bit32.rshift(code, 6)
                    return code
                end)(), 0x3f))
                bytes[(function() 
                    index+=1
                    return index 
                end)()] = bit32.bor(0x80, bit32.band(code, 0x3f))
            else
                code = 0x10000 + bit32.bor(bit32.lshift(bit32.band(code, 0x3ff), 10), bit32.band(key:byte((function()
                    index+=1
                    return index
                end)()), 0x3ff))
                bytes[(function() 
                    index+=1
                    return index 
                end)()] = bit32.bor(0xf0, (function() 
                    code = bit32.rshift(code, 18)
                    return code
                end)())
                bytes[(function() 
                    index+=1
                    return index 
                end)()] = bit32.bor(0x80, bit32.band((function() 
                    code = bit32.rshift(code, 12)
                    return code
                end)(), 0x3f))
                bytes[(function() 
                    index+=1
                    return index 
                end)()] = bit32.bor(0x80, bit32.band((function() 
                    code = bit32.rshift(code, 6)
                    return code
                end)(), 0x3f))
                bytes[(function() 
                    index+=1
                    return index 
                end)()] = bit32.bor(0x80, bit32.band(code, 0x3f))
            end
            i +=1
        end
        key = bytes
    end

    if #key > 64 then
        key = (sha256.new(is224, true):update(key) :: Sha256):array()
    end

    local oKeyPad = {}
    local iKeyPad = {}

    i=0
    while i < 64 do
        local b: number
        if typeof(key) == 'string' then
            b = tonumber(key:sub(i+1, i+1)) or 0
        elseif typeof(key) == 'table' then
            b = key[i]
        end
        oKeyPad[i] = 0x5c ^ b
        iKeyPad[i] = 0x36 ^ b
        i += 1
    end

    local self = sha256.new(is224, sharedMemory) :: HmacSha256
    self:update(iKeyPad)
    self.oKeyPad = oKeyPad
    self.inner = true
    self.sharedMemorey = sharedMemory or false

    return self
end

function hmacSha256.finalize(self)
    sha256.finalize(self)
    if self.inner then
        self.inner = false
        local innerHash = self:array()
        self:update(self.oKeyPad)
        self:update(innerHash)
        self:finalize()
    end
end

function createOutputMethod(outputType: "hash" | "array" | "hex" , is224): { [string]: any }
    return { 
        __call = function(message)
            return ((sha256.new(is224, true):update(message) :: any) :: { [string]: () -> () })[outputType]();
        end 
    }
end

function createMethod(is224: boolean?): {
    create: () -> Sha256,
    update: (message: string) -> Sha256,
    hash: (message: string) -> Sha256,
    array: (message: string) -> Sha256,
    hex: (message: string) -> Sha256,
}
    local method = createOutputMethod("hex", is224)
    method.create = function() 
        return sha256.new(is224)
    end
    method.update = function(message)
        return method.create().update(message)
    end
    method['hash'] = function(message)
        return ((sha256.new(is224, true):update(message) :: any) :: { [string]: () -> () })['hash']();
    end 
    method['array'] = function(message)
        return ((sha256.new(is224, true):update(message) :: any) :: { [string]: () -> () })['array']();
    end 
    method['hex'] = function(message)
        return ((sha256.new(is224, true):update(message) :: any) :: { [string]: () -> () })['hex']();
    end 
    return method
end

function createHmacOutputMethod(outputType, is224)
    return function(key, message)
        return ((hmacSha256.new(key, is224, true):update(message)::any)::{ [string]: () -> () })[outputType]()
    end
end

function createHmacMethod(is224)
    local method = { call = createHmacOutputMethod('hex', is224) }
    method.create = function(key)
        return hmacSha256.new(key, is224)
    end
    method.update = function(key, message)
        return method.create(key):update(message)
    end
    method['hex'] = createHmacOutputMethod('hex', is224)
    method['array'] = createHmacOutputMethod('array', is224)
    method['hash'] = createHmacOutputMethod('hash', is224)

    return method
end

return createMethod()