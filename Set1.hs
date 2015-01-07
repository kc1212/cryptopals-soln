
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString as NonLazyB
import qualified Data.ByteString.Base64.Lazy as B64
import qualified Data.ByteString.Base16.Lazy as B16
import qualified Data.ByteString.Base64 as NonLazyB64
import qualified Data.ByteString.Base16 as NonLazyB16
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified Data.ByteString.Char8 as NonLazyC8
import Data.List (sort, sortBy)
import Data.Word (Word8)
import Data.Int (Int64)
import Data.Char
import Data.Bits
import Data.Byteable
import Debug.Trace
import Crypto.Cipher.AES


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

byteByteXor :: B.ByteString -> B.ByteString -> B.ByteString
byteByteXor a b = B.pack $ B.zipWith xor a b

hexByteXor :: String -> B.ByteString -> B.ByteString
hexByteXor a b = byteByteXor (decodeHexStr a) b

hexHexXor :: String -> String -> B.ByteString
hexHexXor a b = byteByteXor (decodeHexStr a) (decodeHexStr b)

testChallenge2 :: Bool
testChallenge2 = hexHexXor hexStr2a hexStr2b == decodeHexStr hexStr2ans
-- result of xor should be "the kid don't play"


-- challenge 3 ----------------------------------------------------------------
hexStr3 :: String
hexStr3 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

isPrintAndAscii :: Char -> Bool
isPrintAndAscii = \c -> isPrint c && isAscii c

isAllPrintAndAscii :: String -> Bool
isAllPrintAndAscii str = all isPrintAndAscii str

-- TODO everything toLower?
isEnglish :: [String] -> String -> Bool
isEnglish dict str =
    let
        wordList = words str
        threshold = length wordList `div` 2
        minWordCount = length str `div` 8
        maxWordCount = length str `div` 3
        wordCount = length [ x | x <- wordList, binSearch x dict, isAllPrintAndAscii x ]
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

findXorKeyHex :: (String -> Bool) -> String -> [(Bool,B.ByteString,String)]
findXorKeyHex testf str = findXorKeyByte testf $ decodeHexStr str

findXorKeyByte :: (String -> Bool) -> B.ByteString -> [(Bool,B.ByteString,String)]
findXorKeyByte testf str =
    let
        len = B.length str
        keys = [ C8.pack $ replicate (fromIntegral len) y | x <- [0..127], let y = chr x, isPrintAndAscii y ]
    in
        filter (\(x,_,_) -> x) $
            map (\k ->
                    let str' = C8.unpack $ byteByteXor str k
                    in (testf str', k, str'))
                keys

testChallenge3 =
    do
        dict <- getDictionary "words.txt"
        return $ findXorKeyHex (isEnglish dict) hexStr3
-- result appears to be "Cooking MC's like a pound of bacon"

-- challenge 4 ----------------------------------------------------------------
findXorKeysFromFile :: FilePath -> IO [(Bool,B.ByteString,String)]
findXorKeysFromFile f =
    do
        contentsRaw <- readFile f
        dict <- getDictionary "words.txt"
        return $ concatMap (findXorKeyHex (isEnglish dict)) (lines contentsRaw)

testChallenge4 = findXorKeysFromFile "4.txt"
-- result appears to be "Now that the party is jumping\n"


-- challenge 5 ----------------------------------------------------------------
plainStr5 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
keyStr5 = "ICE"
hexStr5 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

repeatXor :: B.ByteString -> B.ByteString -> B.ByteString
-- repeatXor content pattern | trace (show content ++ ", " ++ show (B.length content) ++ ", " ++ show pattern) False = undefined
repeatXor content pattern =
    B.pack $ B.zipWith xor content key
    where key = B.take (B.length content) (B.cycle pattern)

repeatCharXor :: String -> String -> B.ByteString
repeatCharXor str pattern = repeatXor (C8.pack str) (C8.pack pattern)

testChallenge5 = decodeHexStr hexStr5 == repeatCharXor plainStr5 keyStr5


-- challenge 6 ----------------------------------------------------------------
plainStr6a = "this is a test"
plainStr6b = "wokka wokka!!!"

hammingDistByte :: Word8 -> Word8 -> Int
hammingDistByte a b =
    length $ filter (==True) [testBit a x /= testBit b x | x <- [0..7]]

hammingDist :: B.ByteString -> B.ByteString -> Int
hammingDist a b = sum $ zipWith hammingDistByte (B.unpack a) (B.unpack b)

hammingDistBetweenChunks :: Fractional a => Int -> B.ByteString -> a
hammingDistBetweenChunks sz content =
    let
        chunks = toChuncks (fromIntegral sz) content
        n = length chunks - 1
        odds = [ x | x <- [0..n], odd x ]
        evens = [ x | x <- [0..n], even x ]
        pairChunks = zip (map (chunks !!) odds) (map (chunks !!) evens)
        len = fromIntegral (length pairChunks)
    in
        fromIntegral (sum $ map (\(a,b) -> hammingDist a b) pairChunks) / len

smallestHammingDist :: (Ord a, Fractional a) => [Int] -> B.ByteString -> [(Int,a)]
smallestHammingDist ns content =
    sortBy (\(_,x) (_,y) -> compare x y) distances
    where
        distances = zip ns (map avgHammingDist ns)
        avgHammingDist x = hammingDistBetweenChunks x content / fromIntegral x

toChuncks :: Int64 -> B.ByteString -> [B.ByteString]
toChuncks n xs
    | n <= 0 = error "n must be greater than zero"
    | B.length xs == 0 = []
    | otherwise =
        let (a, b) = B.splitAt n xs
        in [a] ++ toChuncks n b

rightOrError :: Either String b -> b
rightOrError (Left a)  = error a
rightOrError (Right b) = b

base64ToByteString :: String -> B.ByteString
base64ToByteString str = rightOrError $ B64.decode $ C8.pack str

base64ToNonLazyByteString :: String -> NonLazyB.ByteString
base64ToNonLazyByteString str = rightOrError $ NonLazyB64.decode $ NonLazyC8.pack str

-- could use this instead of dictionary search
goodHistogram :: String -> Bool
goodHistogram str =
    let
        len = fromIntegral $ length str
        allAscii = all isAscii str
        myIsPunctuation x = isPunctuation x && all (x /=) "#$^&*_+=-][}{@\\|/<>~\DEL"
        spaceCheck = (fromIntegral $ length $ filter isSpace str) > (0.025 * len)
        specialCheck = (fromIntegral $ length $ filter (\x -> isAlphaNum x || myIsPunctuation x || isSpace x) str) > (0.95 * len)
    in
        allAscii && spaceCheck && specialCheck

solveSingleBlock :: B.ByteString -> [(Bool, Word8, String)]
-- solveSingleBlock xs | trace (show xs) False = undefined
solveSingleBlock xs =
    filter (\(x,_,_) -> x)
        [ (goodHistogram res, B.head key, res) | key <- keys, let res = C8.unpack (repeatXor xs key) ]
    where keys = [ C8.pack [y] | x <- [0..128], let y = chr x ]

solveMultiBlocks :: [B.ByteString] -> [[(Bool, Word8, String)]]
solveMultiBlocks xss = map solveSingleBlock xss
-- solveMultiBlocks xss = map (findXorKeyByte isAllPrintAndAscii) xss

collateKeys :: [[(Bool, Word8, String)]] -> B.ByteString
collateKeys xss
    | all (\x -> 1 /= length x) xss = error "all the lists should have length of 1!"
    | otherwise = B.pack $ map (\(_,x,_) -> x) (concat xss)

findTheKey f =
    do
        contentRaw <- readFile f
        let content  = base64ToByteString $ concat $ lines contentRaw
        let (dist,_) = head $ smallestHammingDist [2..40] content
        let contentT = B.transpose $ toChuncks (fromIntegral dist) content
        -- print $ solveMultiBlocks $ contentT
        let key = collateKeys $ solveMultiBlocks $ contentT
        print $ "key is: " ++ C8.unpack key
        print $ "message is: "
        print $ C8.unpack $ repeatXor content key
        -- print $ length $ filter null $ solveMultiBlocks $ content'

testChallenge6a = 37 == hammingDist (C8.pack plainStr6a) (C8.pack plainStr6b)
testChallenge6 = findTheKey "6.txt"


-- challenge 7 ----------------------------------------------------------------

testChallenge7 = do
    contentRaw <- readFile "7.txt"
    let ct = base64ToNonLazyByteString $ concat $ lines contentRaw
    let key = initAES $ NonLazyC8.pack "YELLOW SUBMARINE"
    print " result is: "
    print $ decryptECB key ct



main =
    do
        putStrLn "challenge 1"
        print testChallenge1

        putStrLn "challenge 2"
        print testChallenge2

        putStrLn "challenge 3"
        res3 <- testChallenge3
        print res3

        -- this takes some time to run...
        -- putStrLn "challenge 4"
        -- res4 <- testChallenge4
        -- print res4

        putStrLn "challenge 5"
        print testChallenge5

        putStrLn "challenge 6"
        res6 <- testChallenge6

        print "done"



