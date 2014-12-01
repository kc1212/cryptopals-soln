
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Base64.Lazy as B64
import qualified Data.ByteString.Base16.Lazy as B16
import qualified Data.ByteString.Lazy.Char8 as C8
import Data.Char (chr, isAscii, isPrint, toLower)
import Data.List (sort)
import Data.Bits
import Data.Word (Word8)


-- challenge 1

hexStr1 :: String
hexStr1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
-- I'm killing your brain like a poisonous mushroom

base64Str1 :: String
base64Str1 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

decodeHexStr :: String -> B.ByteString
decodeHexStr x =
    let decodedStr = B16.decode $ C8.pack x
    in if C8.null $ snd decodedStr
        then fst decodedStr
        else error "decoding hex failed"

hexToBase64 :: String -> String
hexToBase64 x = C8.unpack $ B64.encode $ decodeHexStr x

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

-- TODO everything toLower?
isEnglish :: [String] -> String -> Bool
isEnglish dict str =
    let
        wordList = words str
        threshold = length wordList `div` 2
        isPrintAndAscii str = all (\c -> isPrint c && isAscii c) str
        minWordCount = length str `div` 8
        maxWordCount = length str `div` 3
        wordCount = length [ x | x <- wordList, binSearch x dict, isPrintAndAscii x ]
    in
        wordCount > minWordCount
        && wordCount > threshold
        && wordCount < maxWordCount

binSearch :: Ord a => a -> [a] -> Bool
binSearch x xs = doBinSearch x xs (0, length xs - 1)

doBinSearch :: Ord a => a -> [a] -> (Int,Int) -> Bool
doBinSearch x xs (min,max)
    | min == max = if mid == x then True else False
    | mid < x    = doBinSearch x xs (half+1, max)
    | mid > x    = doBinSearch x xs (min,half)
    | mid == x   = True
    | otherwise  = error "critical error!"
    where
        mid  = xs !! half
        half = (max + min) `div` 2

getDictionary :: FilePath -> IO [String]
getDictionary f = readFile f >>= \x -> return $ sort $ lines x

findXorKey :: [String] -> String -> [(Bool,Char,String)]
findXorKey dict str =
    let
        keys = [chr x | x <- [20..126]]
        len = length str
    in
        filter (\(x,_,_) -> x) $
            map (\key -> let str' = C8.unpack $ hexByteXor str (C8.pack $ replicate len key)
                         in (isEnglish dict str', key, str'))
                keys

testChallenge3 =
    do
        dict <- getDictionary "words.txt"
        return $ findXorKey dict hexStr3
-- result appears to be "Cooking MC's like a pound of bacon"

-- challenge 4 ----------------------------------------------------------------
findXorKeysFromFile :: FilePath -> IO [(Bool,Char,String)]
findXorKeysFromFile f =
    do
        contentsRaw <- readFile f
        dict <- getDictionary "words.txt"
        return $ concatMap (findXorKey dict) (lines contentsRaw)

testChallenge4 = findXorKeysFromFile "4.txt"
-- result appears to be "Now that the party is jumping\n"


-- challenge 5 ----------------------------------------------------------------
plainStr5 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
keyStr5 = "ICE"
hexStr5 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

charXor :: Char -> Char -> Char
charXor x y = toEnum $ xor (fromEnum x) (fromEnum y)

repeatXor :: String -> String -> B.ByteString
repeatXor str pattern =
    C8.pack $ C8.zipWith charXor (C8.pack str) (C8.pack key)
    where
        key = take (length str) (cycle pattern)

testChallenge5 = decodeHexStr hexStr5 == repeatXor plainStr5 keyStr5


-- challenge 6 ----------------------------------------------------------------
plainStr6a = "this is a test"
plainStr6b = "wokka wokka!!!"

hammingDistByte :: Word8 -> Word8 -> Int
hammingDistByte a b =
    length $ filter (==True) [testBit a x /= testBit b x | x <- [0..7]]

hammingDist :: B.ByteString -> B.ByteString -> Int
hammingDist a b = sum $ zipWith hammingDistByte (B.unpack a) (B.unpack b)

testChallenge6a = 37 == hammingDist (C8.pack plainStr6a) (C8.pack plainStr6b)

-- main = testChallenge4 >>= \x -> print x


