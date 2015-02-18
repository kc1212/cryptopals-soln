
module Set2
( pkcs7
) where

import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified Data.Map as Map
import Control.Monad
import Data.List
import Data.List.Split
import Data.Int (Int64)
import Data.Word (Word8)
import Crypto.Cipher.AES
import System.Random
import Debug.Trace

import Common
import Set1

errBlockSize :: a
errBlockSize = error "wrong AES block size"

myEncryptECB :: AES -> B.ByteString -> B.ByteString
myEncryptECB aes x =
    B.fromStrict $ encryptECB aes (B.toStrict x)

myDecryptECB :: AES -> B.ByteString -> B.ByteString
myDecryptECB aes x =
    B.fromStrict $ decryptECB aes (B.toStrict x)

myEncryptCBC :: AES -> B.ByteString -> B.ByteString -> B.ByteString
myEncryptCBC aes iv pt
    | B.length iv == aesBs =
        B.concat $ tail $ scanl (\x y -> myEncryptECB aes (byteByteXor x y)) iv ptChunks
    | otherwise = errBlockSize
    where ptChunks = toChunksN 16 (pkcs7 aesBs pt)

myDecryptCBC :: AES -> B.ByteString -> B.ByteString -> B.ByteString
myDecryptCBC aes iv ct
    | B.length iv == aesBs =
        B.concat $ map (\(x,y) -> byteByteXor y (myDecryptECB aes x)) ctPairs
    | otherwise = errBlockSize
    where
        ctChunks = toChunksN 16 ct
        ctPairs = zip ctChunks (iv : init ctChunks)

testCBC :: B.ByteString
testCBC =
    let
        x = C8.pack "testing CBC... randomly typing on the my t420 keyboard"
        key = initAES $ B.toStrict $ pkcs7 16 $ C8.pack "hello!!!"
        iv = C8.pack $ "0000000000000000"
    in
        myDecryptCBC key iv (myEncryptCBC key iv x)

-- TODO possibly take RandomGen as input?
genBytes :: Int -> IO B.ByteString
genBytes n = do
    gen <- newStdGen
    return $ B.pack $ take n $ randoms gen

genKey :: IO AES
genKey = genBytes 16 >>= return . initAES . B.toStrict

ecbOracle11 :: AES -> Bool -> B.ByteString -> IO B.ByteString
ecbOracle11 key isCbc pt = do
    before  <- getStdRandom (randomR (5,10)) >>= genBytes
    after   <- getStdRandom (randomR (5,10)) >>= genBytes
    iv      <- genBytes 16
    -- key     <- genKey
    let ptx = pkcs7 16 $ B.append before (B.append pt after)
    return $ if isCbc then myEncryptCBC key iv ptx else myEncryptECB key ptx

hasRepeatedBlock :: (Int -> Bool) -> B.ByteString -> Bool
hasRepeatedBlock cmp ct =
    let cts = toChunksN aesBs ct
    in any (cmp . length) (group $ sort cts)

findBlockSize :: AES -> B.ByteString -> Maybe Int
findBlockSize key unkStr =
    let myStr = map (\x -> C8.pack $ replicate x 'A') (filter even [1..64])
        ress = map (\x -> myEncryptECB key (pkcs7 16 $ B.append x unkStr)) myStr
    in elemIndex True $ map (\x -> let xs = toChunksN 16 x in xs !! 0 == xs !! 1) ress

-- the key is cipher text, value is plain text
createCtPtMap :: AES -> B.ByteString -> Map.Map B.ByteString B.ByteString
createCtPtMap key xs =
    Map.fromList $ map (\x -> (myEncryptECB key x, x)) (map (B.snoc xs) [0..255])

iHateMaybe :: Maybe a -> a
iHateMaybe (Just a) = a
iHateMaybe Nothing = error "I loathe Nothing more!"

doChallenge12 :: IO ()
doChallenge12 = do
    unkText <- fmap (base64ToByteString . concat . lines) (readFile "12.txt")
    key <- genKey

    putStr "block size: "
    let bs = iHateMaybe $ fmap (fromIntegral . (+1)) (findBlockSize key unkText)
    putStrLn $ show $ bs

    let ecbOracle12 pt = myEncryptECB key $ pkcs7 bs (B.append pt unkText)

    putStr "is ECB: "
    putStrLn $ show $ hasRepeatedBlock (>= 2) $ ecbOracle12 (B.replicate 64 12)

    let breakEcbSimple ctr pre =
            let
                preMap = createCtPtMap key pre
                initBlock = B.take (B.length pre + 1) (ecbOracle12 (B.take ctr pre))
                solvedBlock = Map.lookup initBlock preMap
            in
                if ctr == 0 || solvedBlock == Nothing
                then pre
                else breakEcbSimple (ctr-1) (B.tail (iHateMaybe solvedBlock))

    -- length should always be a multiple of 16 due to pkcs7 padding
    let ctLen = B.length $ ecbOracle12 (C8.pack "")
    putStrLn $ if mod ctLen bs == 0
               then "starting decryptiong (" ++ show ctLen ++ ")..."
               else error "ctLen not multiple of 16"

    -- assuming the text won't start with \0
    putStr $ C8.unpack $ B.dropWhile (==0) $ breakEcbSimple (ctLen-1) (B.replicate (ctLen-1) 0)


type ProfileObj = [(String,String)]

decodeProfile :: String -> ProfileObj
decodeProfile inp =
    let innerSplit x =
            let xs = splitOn "=" x
            in if length xs == 2 then (xs !! 0, xs !! 1) else error "parse error!"
    in map innerSplit (splitOn "&" inp)

profileFor :: String -> ProfileObj
profileFor inp =
    [("email", delete '&' $ delete '=' inp), ("uid", "10"), ("role", "user")]

encodeProfile :: ProfileObj -> String
encodeProfile obj =
    init $ concatMap (\x -> (fst x) ++ '=':(snd x) ++ "&") obj

doChallenge13 :: IO ()
doChallenge13 = do
    key <- genKey
    let oracle = myEncryptECB key . pkcs7 aesBs . C8.pack
    let profile1 = encodeProfile $ profileFor "fooz@barz.com"
    -- email=fooz@barz.com&uid=10&role=user    user begins at 32, third
    -- 0    5    10   15   20   25   30   35
    let ct1s = toChunksN aesBs $ oracle profile1

    let profile2 = encodeProfile $ profileFor ("AAAAAAAAAAadmin" ++ replicate 12 '\f')
    -- email=AAAAAAAAAAadmin----------&uid=10&role=user   admin begins at 16, second
    -- 0    5    10   15   20   25   30   35
    let ct2s = toChunksN aesBs $ oracle profile2

    -- now reconstruct a forged ct from the two previous ct
    -- we have forged the admin role!
    putStrLn $ show $ myDecryptECB key $ B.concat [ ct1s !! 0, ct1s !! 1, ct2s !! 1 ]

-- keep everything after the repated blocks, drop everything before it
keepAfterRepeats :: Int64 -> (Int -> Bool) -> B.ByteString -> B.ByteString
keepAfterRepeats bs cmp inp =
    let inps = toChunksN bs inp
        filtered = filter (cmp . length) (group $ sort inps)
        dropStuff x = B.concat $ drop (1+(last $ elemIndices x inps)) inps
    in if length filtered == 0 then C8.pack ""
        else if length (head filtered) == 0 then error "critical error!"
        else dropStuff (head $ head filtered)

doChallenge14 :: IO ()
doChallenge14 = do
    unkText <- fmap (base64ToByteString . concat . lines) (readFile "12.txt")
    key <- genKey

    let tries = 500
    let myWord = 65
    let myBlocks = 2

    -- AES-128-ECB( random-prefix || attacker-controlled || target-bytes, random-key )
    let ecbOracle14 pt = do
        randomBytes <- newStdGen >>= \g -> genBytes (head $ randomRs (0,255) g)
        return $ myEncryptECB key $ pkcs7 aesBs (B.append randomBytes $ B.append pt unkText)

    -- find the length of the target-bytes
    let ctLen = do
        cts <- replicateM tries (ecbOracle14 (B.replicate (aesBs*myBlocks) myWord))
        return $ head $ filter (>0) $
            map (B.length . keepAfterRepeats aesBs (== fromIntegral myBlocks)) cts

    -- append 4 blocks before 'pre', run the oracle many times, until 'pre' starts at the block boundry
    -- TODO this algorithm cannot decrypt all the target-bytes
    let breakEcbHarder ctr pre = do
        listTry <- replicateM tries $
                        ecbOracle14 (B.append (B.replicate (aesBs*myBlocks) myWord) (B.take ctr pre))
        let goodTry = head $ filter (\x -> let l = B.length x in l > 0 && mod l aesBs == 0) $
                        map (keepAfterRepeats aesBs (== fromIntegral myBlocks)) listTry

        let preMap = createCtPtMap key pre
        let initBlock = B.take (B.length pre + 1) goodTry
        let solvedBlock = Map.lookup initBlock preMap

        if ctr == 0 || solvedBlock == Nothing
        then return pre
        else breakEcbHarder (ctr-1) (B.tail (iHateMaybe solvedBlock))

    ctLen >>= \x -> breakEcbHarder (x-1) (B.replicate (x-1) 0) >>= return . C8.unpack . B.dropWhile (==0) >>= putStr

prepUserData :: AES -> B.ByteString -> B.ByteString -> String -> B.ByteString -> B.ByteString
prepUserData key iv front rawInp back =
    let inp = C8.pack $ delete '&' $ delete '=' rawInp
    in myEncryptCBC key iv (pkcs7 aesBs (B.append front $ B.append inp back))

checkUserData :: AES -> B.ByteString -> B.ByteString -> Bool
checkUserData key iv ct =
    let pt = fmap C8.unpack (validPkcs7 $ myDecryptCBC key iv ct)
        res = fmap (all (\(x,y) -> x == "admin" && y == "true")) (fmap decodeProfile pt)
    in case res of
        Nothing -> error "padding error"
        Just True -> True
        Just False -> False


doChallenge16 = do
    key <- genKey
    iv  <- genBytes 16

    let s1 = C8.pack "comment1=cooking%20MCs;userdata="
    let s2 = C8.pack ";comment2=%20like%20a%20pound%20of%20bacon"
    --                 0       8       16
    --                 admin=true;AAAA=

    -- extra length needed to fill s1 to block boundry
    let extraLen = let l = mod (B.length s1) aesBs in if l == 0 then 0 else aesBs - l
    let pt = C8.unpack $ B.replicate (aesBs + extraLen) 65
    let ct = prepUserData key iv s1 pt s2

    let loc = B.length s1 + extraLen
    let fb = B.append
                (B.append (B.replicate loc 0) (C8.pack "admin=true;AAAA="))
                (B.replicate (B.length ct - loc - aesBs) 0)

    let ct' = byteByteXor fb ct

    -- putStrLn $ show (B.length s1) ++ ", " ++ show (B.length s2) ++ ", " 
    --     ++ show loc ++ ", " ++ show extraLen ++ ", " ++ show (B.length fb)

    -- TODO change this to use the checkUserData function
    putStrLn $ C8.unpack $ myDecryptCBC key iv ct'

main = do
    putStrLn "challenge 9:"
    let res9 = pkcs7 20 (C8.pack "YELLOW SUBMARINE")
    putStrLn $ show res9
    putStrLn $ show $ B.unpack res9
    putStrLn ""

    putStrLn "challenge 10:"
    putStrLn $ show testCBC
    ct10 <- fmap (base64ToByteString . concat . lines) (readFile "10.txt")
    let key10 = initAES $ B.toStrict $ C8.pack "YELLOW SUBMARINE"
    let iv10 = C8.pack $ "0000000000000000"
    let pt10 = C8.unpack $ myDecryptCBC key10 iv10 ct10
    putStr pt10
    putStrLn ""

    putStrLn "challenge 11:"
    isCbc <- getStdRandom random
    ct11 <- genKey >>= \key -> ecbOracle11 key isCbc (C8.pack pt10) -- TODO need randomly generate plain text
    putStrLn $ if isCbc /= (hasRepeatedBlock (>= 2) ct11)
                then "prediciton correct!" else "prediction wrong..."
    putStrLn ""

    putStrLn "challenge 12:"
    doChallenge12
    putStrLn ""

    putStrLn "challenge 13:"
    doChallenge13
    putStrLn ""

    putStrLn "challenge 14:"
    doChallenge14
    putStrLn ""

    putStrLn "challenge 15:"
    putStrLn $ show $ fmap C8.unpack (validPkcs7 (C8.pack "ICE ICE BABY\x04\x04\x04\x04"))
    putStrLn $ show $ fmap C8.unpack (validPkcs7 (C8.pack "ICE ICE BABY\x05\x05\x05\x05"))
    putStrLn $ show $ fmap C8.unpack (validPkcs7 (C8.pack "ICE ICE BABY\x03\x03\x03"))
    putStrLn ""

    putStrLn "done"



