
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Base64.Lazy as B64
import qualified Data.ByteString.Base16.Lazy as B16
import qualified Data.ByteString.Lazy.Char8 as BC8


-- challenge 1

hexStr :: String
hexStr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

base64Str :: String
base64Str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

decodeHexStr :: String -> B.ByteString
decodeHexStr x =
    let decodedStr = B16.decode $ BC8.pack x
    in if BC8.null $ snd decodedStr
        then fst decodedStr
        else error "decoding hex failed"

hexToBase64 :: String -> String
hexToBase64 x = BC8.unpack $ B64.encode $ decodeHexStr x

testChallenge1 :: Bool
testChallenge1 = hexToBase64 hexStr == base64Str

-- challenge 2
-- hexXor :: String -> String -> B.ByteString


