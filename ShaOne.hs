
module ShaOne (shaOne, shaOneBase64) where

import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified Data.ByteString.Base64.Lazy as B64
import Data.Binary
import Data.Bits

import Common (toChunksN, bbXor)

-- since we're taking bytestring as input to our sha1 function, we can assume
-- the input parameter is always on a byte boundry

type Bs = B.ByteString
type HTuple = (Word32, Word32, Word32, Word32, Word32)

bitNot :: Word32 -> Word32
bitNot x = x `xor` 0xFFFFFFFF

toChunksNWord32 :: Bs -> [Word32]
toChunksNWord32 ws =
    let res = map decode (toChunksN 4 ws)
    in case length res of
        16 -> res
        _  -> error "length of toChunksNWord32 is not 16!"

preProcess :: Bs -> Bs
preProcess inp =
    let len = B.length inp
        extraLen = (64 + 56 - (len+1) `mod` 64) `mod` 64
        rest = 128 `B.cons` (B.replicate extraLen 0) `B.append` encode len
    in B.append inp rest

-- extend 16*32bit words to 80*32bit words
extend :: [Word32] -> [Word32]
extend x =
    let res = doExtend 0 x
    in if length x /= 16 then error "bad extend input"
        else if length res /= 80 then error "bad extend output"
        else res

doExtend :: Int -> [Word32] -> [Word32]
doExtend 80 ws = ws
doExtend i ws =
    if i >= 0 && i < 16
        then doExtend (i+1) ws
    else if i >= 16 && i < 80
        then let w = (ws!!(i-3) `xor` ws!!(i-8) `xor` ws!!(i-14) `xor` ws!!(i-16)) `rotateL` 1
             in doExtend (i+1) (ws ++ [w])
    else error "invalid index i"

doMainLoop :: HTuple -> [Word32] -> Int -> HTuple
doMainLoop hTuple _ 80 = hTuple
doMainLoop (a,b,c,d,e) w i =
    let final f k =
            let temp = (a `rotateL` 5 + f + e + k + (w!!i))
                e'   = d
                d'   = c
                c'   = b `rotateL` 30
                b'   = a
                a'   = temp
            in (a',b',c',d',e')
    in if 0 <= i && i <= 19
            then doMainLoop (final ((b .&. c) .|. ((bitNot b) .&. d)) 0x5A827999) w (i+1)
        else if 20 <= i && i <= 39
            then doMainLoop (final (b `xor` c `xor` d) 0x6ED9EBA1) w (i+1)
        else if 40 <= i && i <= 59
            then doMainLoop (final ((b .&. c) .|. (b .&. d) .|. (c .&. d)) 0x8F1BBCDC) w (i+1)
        else if 60 <= i && i <= 79
            then doMainLoop (final (b `xor` c `xor` d) 0xCA62C1D6) w (i+1)
        else
            error ("doMainLoop out of range: " ++ show i)

mainLoop :: HTuple -> [Word32] -> HTuple
mainLoop (a,b,c,d,e) w = doMainLoop (a,b,c,d,e) w 0

-- this for a single 512 bit chunk
shaOneOnChunk :: HTuple -> Bs -> HTuple
shaOneOnChunk hTuple chunk = mainLoop hTuple (extend $ toChunksNWord32 chunk)

shaOneOnChunkS :: HTuple -> [Bs] -> HTuple
shaOneOnChunkS hTuple [x] = shaOneOnChunk hTuple x
shaOneOnChunkS hTuple (x:xs) =
    shaOneOnChunkS (shaOneOnChunk hTuple x) xs

shaOne :: Bs -> Bs
shaOne inp =
    let inp' = toChunksN 64 (preProcess inp)
        hs = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0) :: HTuple
        (h0,h1,h2,h3,h4) = shaOneOnChunkS hs inp'
    in B.concat $ map encode (h0:h1:h2:h3:h4:[])

shaOneBase64 :: Bs -> String
shaOneBase64 = C8.unpack . B64.encode . shaOne

