
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import Data.Word (Word8)
import Data.List
import Data.Char
import Data.Bits
import Debug.Trace
import Crypto.Cipher.AES

import Common


-- challenge 1
hexStr1 :: String
hexStr1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
-- I'm killing your brain like a poisonous mushroom

base64Str1 :: String
base64Str1 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

testChallenge1 :: Bool
testChallenge1 = hexToBase64 hexStr1 == base64Str1


-- challenge 2 ----------------------------------------------------------------
hexStr2a = "1c0111001f010100061a024b53535009181c"
hexStr2b = "686974207468652062756c6c277320657965"
hexStr2ans = "746865206b696420646f6e277420706c6179"

testChallenge2 :: Bool
testChallenge2 = hexHexXor hexStr2a hexStr2b == decodeHexStr hexStr2ans
-- result of xor should be "the kid don't play"


-- challenge 3 ----------------------------------------------------------------
hexStr3 :: String
hexStr3 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

isAllPrintAndAscii :: String -> Bool
isAllPrintAndAscii = all isPrintAndAscii

-- -- TODO everything toLower?
-- isEnglish :: [String] -> String -> Bool
-- isEnglish dict str =
--     let
--         wordList = words str
--         threshold = length wordList `div` 2
--         minWordCount = length str `div` 8
--         maxWordCount = length str `div` 3
--         wordCount = length [ x | x <- wordList, binSearch x dict, isAllPrintAndAscii x ]
--     in
--         wordCount > minWordCount
--         && wordCount > threshold
--         && wordCount < maxWordCount
--
-- binSearch :: Ord a => a -> [a] -> Bool
-- binSearch x xs = doBinSearch x xs (0, length xs - 1)
--
-- doBinSearch :: Ord a => a -> [a] -> (Int,Int) -> Bool
-- doBinSearch x xs (min,max)
--     | min == max = if mid == x then True else False
--     | mid < x    = doBinSearch x xs (half+1, max)
--     | mid > x    = doBinSearch x xs (min,half)
--     | mid == x   = True
--     | otherwise  = error "critical error!"
--     where
--         mid  = xs !! half
--         half = (max + min) `div` 2
--
-- getDictionary :: FilePath -> IO [String]
-- getDictionary f = readFile f >>= \x -> return $ sort $ lines x

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

testChallenge3 = findXorKeyHex goodHistogram hexStr3
-- result appears to be "Cooking MC's like a pound of bacon"

-- challenge 4 ----------------------------------------------------------------
findXorKeysFromFile :: FilePath -> IO [(Bool,B.ByteString,String)]
findXorKeysFromFile f =
    do
        contentsRaw <- readFile f
        return $ concatMap (findXorKeyHex goodHistogram) (lines contentsRaw)

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

-- TODO we can simplify this, probably use scanl
hammingDistBetweenChunks :: Fractional a => Int -> B.ByteString -> a
hammingDistBetweenChunks sz content =
    let
        chunks = toChunksN (fromIntegral sz) content
        n = length chunks - 1
        odds = [ x | x <- [0..n], odd x ]
        evens = [ x | x <- [0..n], even x ]
        pairChunks = zip (map (chunks !!) odds) (map (chunks !!) evens)
        len = fromIntegral (length pairChunks)
    in
        fromIntegral (sum $ map (uncurry hammingDist) pairChunks) / len

smallestHammingDist :: (Ord a, Fractional a) => [Int] -> B.ByteString -> [(Int,a)]
smallestHammingDist ns content =
    sortBy (\(_,x) (_,y) -> compare x y) distances
    where
        distances = zip ns (map avgHammingDist ns)
        avgHammingDist x = hammingDistBetweenChunks x content / fromIntegral x

-- could use this instead of dictionary search
goodHistogram :: String -> Bool
goodHistogram str =
    let
        len = fromIntegral $ length str
        allAscii = all isAscii str
        myIsPunctuation x = isPunctuation x && notElem x "#$^&*_+=-][}{@\\|/<>~\DEL"
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
solveMultiBlocks = map solveSingleBlock
-- solveMultiBlocks xss = map (findXorKeyByte isAllPrintAndAscii) xss

collateKeys :: [[(Bool, Word8, String)]] -> B.ByteString
collateKeys xss
    | all (\x -> 1 /= length x) xss = error "all the lists should have length of 1!"
    | otherwise = B.pack $ map (\(_,x,_) -> x) (concat xss)

findTheKey f = do
    content <- fmap (base64ToByteString . concat . lines) (readFile f)
    let (dist,_) = head $ smallestHammingDist [2..40] content
    let contentT = B.transpose $ toChunksN (fromIntegral dist) content
    -- print $ solveMultiBlocks $ contentT
    let key = collateKeys $ solveMultiBlocks contentT
    print $ "key is: " ++ C8.unpack key
    print $ "message is: "
    putStr $ C8.unpack $ repeatXor content key
    -- print $ length $ filter null $ solveMultiBlocks $ content'

testChallenge6a = 37 == hammingDist (C8.pack plainStr6a) (C8.pack plainStr6b)
testChallenge6 = findTheKey "6.txt"


-- challenge 7 ----------------------------------------------------------------

testChallenge7 = do
    ct <- fmap (B.toStrict . base64ToByteString . concat . lines) (readFile "7.txt")
    let key = initAES $ B.toStrict $ C8.pack "YELLOW SUBMARINE"
    putStr $ C8.unpack $ B.fromStrict $ decryptECB key ct


-- challenge 8 ----------------------------------------------------------------

hammingDistAllComboInList :: [B.ByteString] -> Int
hammingDistAllComboInList xs =
    sum $ map (uncurry hammingDist) [ (x1,x2) | x1 <- xs, x2 <- xs ]

-- AES block size is 16
testChallenge8 = do
    cts <- fmap (map decodeHexStr . lines) (readFile "8.txt")
    let dists = map (hammingDistAllComboInList . toChunksN 16) cts
    let minElem = minimum dists
    print $ (show $ elemIndex minElem dists) ++ "th element is ECB with hamming distance of " ++ (show minElem)



main =
    do
        putStrLn "challenge 1"
        print testChallenge1

        putStrLn "challenge 2"
        print testChallenge2

        -- TODO this takes some time to run, need to optimize
        putStrLn "challenge 3"
        print  testChallenge3

        -- TODO this takes some time to run, need to optimize
        putStrLn "challenge 4"
        res4 <- testChallenge4
        print res4

        putStrLn "challenge 5"
        print testChallenge5

        putStrLn "challenge 6"
        res6 <- testChallenge6

        putStrLn "challenge 7"
        res7 <- testChallenge7

        putStrLn "challenge 8"
        res8 <- testChallenge8

        print "done"



