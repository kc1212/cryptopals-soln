
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import Data.Binary
import Data.Bits

import Common (toChunksN, bbXor)

-- since we're taking bytestring as input to our sha1 function, we can assume
-- the input parameter is always on a byte boundry

type Bs = B.ByteString

h0 = 0x67452301
h1 = 0xEFCDAB89
h2 = 0x98BADCFE
h3 = 0x10325476
h4 = 0xC3D2E1F0

preProcess :: Bs -> Bs
preProcess inp =
    let len = B.length inp
        extraLen = (64 + 56 - (len+1) `mod` 64) `mod` 64
        rest = 128 `B.cons` (B.replicate extraLen 0) `B.append` encode len
    in B.append inp rest

xorList :: [Bs] -> Bs
xorList [] = undefined
xorList [a] = a
xorList [a,b] = a `bbXor` b
xorList (x:xs) =
    x `bbXor` (xorList xs)

bsRotateL32 :: Bs -> Int -> Bs
bsRotateL32 x i = encode ((decode x :: Word32) `rotateL` i)

extend :: [Bs] -> [Bs]
extend = doExtend 0

doExtend :: Int -> [Bs] -> [Bs]
doExtend i ws =
    if i >= 0 && i < 16
        then doExtend (i+1) ws
    else if i >= 16 && i < 80
        then let w = xorList [ws!!(i-3), ws!!(i-8), ws!!(i-14), ws!!(i-16)] `bsRotateL32` 1
             in doExtend (i+1) (ws ++ [w])
    else if i == 80
        then ws
    else error "invalid index i"




