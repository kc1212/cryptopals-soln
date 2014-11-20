
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Base64.Lazy as B64
import qualified Data.ByteString.Base16.Lazy as B16
import qualified Data.ByteString.Lazy.Char8 as BC8
import Data.Bits
import Data.Char


-- challenge 1
hexStr1 :: String
hexStr1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

base64Str1 :: String
base64Str1 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

decodeHexStr :: String -> B.ByteString
decodeHexStr x =
    let decodedStr = B16.decode $ BC8.pack x
    in if BC8.null $ snd decodedStr
        then fst decodedStr
        else error "decoding hex failed"

hexToBase64 :: String -> String
hexToBase64 x = BC8.unpack $ B64.encode $ decodeHexStr x

testChallenge1 :: Bool
testChallenge1 = hexToBase64 hexStr1 == base64Str1


-- challenge 2
hexStr2a = "1c0111001f010100061a024b53535009181c"
hexStr2b = "686974207468652062756c6c277320657965"
hexStr2ans = "746865206b696420646f6e277420706c6179"

hexXor :: String -> String -> B.ByteString -- TODO check length, should be equal
hexXor a b = B.pack $ B.zipWith xor (decodeHexStr a) (decodeHexStr b)

testChallenge2 :: Bool
testChallenge2 = hexXor hexStr2a hexStr2b == decodeHexStr hexStr2ans


-- challenge 3

hexStr3 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

-- we assume letter frequency analysis is feasible
isEnglish :: String -> Bool
isEnglish str =
    let
        len = toRational $ length str
        spaceRatio = getRatio ' '
        echoRatio = getRatio 'e'
        alphaRatio = getRatio 'a'
        getRatio x = toRational (length (filter (==x) str)) / len
    in
        spaceRatio > 0.09 && spaceRatio < 0.2 &&
        echoRatio  > 0.06 && echoRatio  < 0.2 ||
        alphaRatio > 0.05 && alphaRatio < 0.2

repeatN 0 _ = []
repeatN x xs = repeatN (x-1) xs ++ xs

findXorKey :: String -> [(Bool,String,String)]
findXorKey str =
    let
        hexChars = [ repeatN (len `div` 2) $ x:[y] | x <- asciiChars, y <- asciiChars ]
        asciiChars = ['0'..'9'] ++ ['a'..'f']
        len = length str
    in filter (\(x,_,_) -> x) $
            map (\key -> let str' = BC8.unpack $ hexXor str key
                    in (isEnglish str', key, str')) hexChars

testChallenge3 = findXorKey hexStr3 -- one of the result is in English





