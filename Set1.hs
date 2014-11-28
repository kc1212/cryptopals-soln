
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Base64.Lazy as B64
import qualified Data.ByteString.Base16.Lazy as B16
import qualified Data.ByteString.Lazy.Char8 as BC8
import Data.Char (chr, isAscii, isPrint, toLower)
import Data.Bits


-- challenge 1

hexStr1 :: String
hexStr1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
-- I'm killing your brain like a poisonous mushroom

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


-- challenge 2 ----------------------------------------------------------------
hexStr2a = "1c0111001f010100061a024b53535009181c"
hexStr2b = "686974207468652062756c6c277320657965"
hexStr2ans = "746865206b696420646f6e277420706c6179"

hexByteXor :: String -> B.ByteString -> B.ByteString
hexByteXor a b = B.pack $ B.zipWith xor (decodeHexStr a) b

hexHexXor :: String -> String -> B.ByteString
hexHexXor a b = hexByteXor a (decodeHexStr b)

testChallenge2 :: Bool
testChallenge2 = hexHexXor hexStr2a hexStr2b == decodeHexStr hexStr2ans
-- result of xor should be "the kid don't play"


-- challenge 3 ----------------------------------------------------------------
hexStr3 :: String
hexStr3 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

-- we assume letter frequency analysis is feasible
-- TODO everything toLower?
isEnglish :: [String] -> String -> Bool
isEnglish dict str =
    let
        wordList = words str
        threshold = (length wordList) `div` 2
        isPrintAndAscii str = all (\c -> isPrint c && isAscii c) str
    in
        length [ x | x <- wordList, elem x dict, isPrintAndAscii x ] > threshold

getDictionary :: FilePath -> IO [String]
getDictionary f = readFile f >>= \x -> return $ lines x

findXorKey :: [String] -> String -> [(Bool,Char,String)]
findXorKey dict str =
    let
        keys = [chr x | x <- [20..126]]
        len = length str
    in filter (\(x,_,_) -> x) $
            map (\key -> let str' = BC8.unpack $ hexByteXor str (BC8.pack $ replicate len key)
                         in (isEnglish dict str', key, str'))
                keys

testChallenge3 =
    do
        dict <- getDictionary "words.txt"
        return $ findXorKey dict hexStr3
-- one of the result is in English, which is
-- Cooking MC's like a pound of bacon

-- challenge 4 ----------------------------------------------------------------
findXorKeysFromFile :: FilePath -> IO [(Bool,Char,String)]
findXorKeysFromFile f =
    do
        contentsRaw <- readFile f
        dict <- getDictionary "words.txt"
        return $ concatMap (findXorKey dict) (lines contentsRaw)

testChallenge4 = findXorKeysFromFile "4.txt"




