
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import Data.Int (Int64)

pkcs7 :: Int64 -> B.ByteString -> B.ByteString
pkcs7 blockSize x =
    let
        tmp = blockSize - mod (B.length x) blockSize
        padCount = if tmp == 0 then blockSize else tmp
    in
        B.append x (B.replicate padCount (fromIntegral padCount))



