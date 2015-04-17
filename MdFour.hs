
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified Data.ByteString.Base64.Lazy as B64
import qualified Data.ByteString.Base16.Lazy as B16
import Data.Binary
import Data.Bits
import Data.Int (Int32)

type StateTuple = (Word32, Word32, Word32, Word32)

bitNot :: Word32 -> Word32
bitNot x = x `xor` 0xFFFFFFFF

rol :: Word32 -> Int -> Word32
rol v n = (v `shiftL` n) .|. (v `shiftR` (32 - n))

r1Ops :: StateTuple -> Word32 -> Int -> Word32
r1Ops (a,b,c,d) xk s = rol (a + ((b .&. c) .|. (bitNot b .&. d))+ xk) s

r2Ops :: StateTuple -> Word32 -> Int -> Word32
r2Ops (a,b,c,d) xk s = rol (a + ((b .&. c) .|. (b .&. d) .|. (c .&. d)) + xk + 0x5a827999) s

r3Ops :: StateTuple -> Word32 -> Int -> Word32
r3Ops (a,b,c,d) xk s = rol (a + (b `xor` c `xor` d) + xk + 0x6ed9eba1) s


