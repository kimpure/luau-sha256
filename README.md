# luau-sha256
luau-sha256 is a library for using sha256 in luau.

## install
pesde
```
pesde add kimpure/sha256
```
submodule
```
git submodule add https://github.com/kimpure/luau-sha256 lune-utf16
```

## how to use
require
```luau
local sha256 = require('path');
```

new
```luau
local newSha256 = sha256.new(is224: boolean, sharedMemory: boolean): Sha256
```

update
```luau
newSha256:update('this luau sha256')
```

hex
```luau
local newHex: string = newSha256:hex()
print(newHex) ---> 118a2e600f622c14eb8730f7cf4fadcdc3b7389133395f404f77fd1419321736
```

Additional features:
```luau
hash: (self: Sha256) -> (),
finalize: (self: Sha256) -> (),
array: (self: Sha256) -> { [number]: number },
```

## note
NOTE BY [js-sha256](https://github.com/emn178/js-sha256)