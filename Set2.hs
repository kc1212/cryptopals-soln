
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

import Set1

-- feels like procedural programming..
pkcs7 :: Int64 -> B.ByteString -> B.ByteString
pkcs7 bs x =
    let
        tmp = bs - mod (B.length x) bs
        padCount = if tmp == 0 then bs else tmp
    in
        B.append x (B.replicate padCount (fromIntegral padCount))

aesBlockSize :: Int64
aesBlockSize = 16 :: Int64

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
    | B.length iv == aesBlockSize =
        B.concat $ tail $ scanl (\x y -> myEncryptECB aes (byteByteXor x y)) iv ptChunks
    | otherwise = errBlockSize
    where ptChunks = toChunksN 16 (pkcs7 aesBlockSize pt)

myDecryptCBC :: AES -> B.ByteString -> B.ByteString -> B.ByteString
myDecryptCBC aes iv ct
    | B.length iv == aesBlockSize =
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

genBytes :: Int -> IO B.ByteString
genBytes n = do
    res <- replicateM n $ getStdRandom random
    return $ B.pack res

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

byteStringHasRepeat :: B.ByteString -> Bool
byteStringHasRepeat ct =
    let cts = toChunksN 16 ct
    in any ((>= 2) . length) (group $ sort cts)

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
    putStrLn $ show $ byteStringHasRepeat $ ecbOracle12 (B.replicate 64 12)

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


type CookieObj = [(String,String)]

decodeCookie :: String -> CookieObj
decodeCookie inp =
    let innerSplit x =
            let xs = splitOn "=" x
            in if length xs == 2 then (xs !! 0, xs !! 1) else error "parse error!"
    in map innerSplit (splitOn "&" inp)

profileFor :: String -> CookieObj
profileFor inp =
    [("email", delete '&' $ delete '=' inp), ("uid", "10"), ("role", "user")]

encodeCookie :: CookieObj -> String
encodeCookie obj =
    init $ concatMap (\x -> (fst x) ++ '=':(snd x) ++ "&") obj

doChallenge13 :: IO ()
doChallenge13 = do
    key <- genKey
    let oracle = myEncryptECB key . pkcs7 16 . C8.pack
    let profile1 = encodeCookie $ profileFor "fooz@barz.com"
    -- email=fooz@barz.com&uid=10&role=user    user begins at 32, third
    -- 0    5    10   15   20   25   30   35
    let ct1s = toChunksN 16 $ oracle profile1

    let profile2 = encodeCookie $ profileFor ("AAAAAAAAAAadmin" ++ replicate 12 '\f')
    -- email=AAAAAAAAAAadmin----------&uid=10&role=user   admin begins at 16, second
    -- 0    5    10   15   20   25   30   35
    let ct2s = toChunksN 16 $ oracle profile2

    -- now reconstruct a forged ct from the two previous ct
    -- we have forged the admin role!
    putStrLn $ show $ myDecryptECB key $ B.concat [ ct1s !! 0, ct1s !! 1, ct2s !! 1 ]


main = do
    putStrLn "challenge 9:"
    let res9 = pkcs7 20 (C8.pack "YELLOW SUBMARINE")
    putStrLn $ show res9
    putStrLn $ show $ B.unpack res9

    putStrLn "challenge 10:"
    putStrLn $ show testCBC
    ct10 <- fmap (base64ToByteString . concat . lines) (readFile "10.txt")
    let key10 = initAES $ B.toStrict $ C8.pack "YELLOW SUBMARINE"
    let iv10 = C8.pack $ "0000000000000000"
    let pt10 = C8.unpack $ myDecryptCBC key10 iv10 ct10
    putStr pt10

    putStrLn "challenge 11:"
    isCbc <- getStdRandom random
    ct11 <- genKey >>= \key -> ecbOracle11 key isCbc (C8.pack pt10) -- TODO need randomly generate plain text
    putStrLn $ if isCbc /= (byteStringHasRepeat ct11)
                then "prediciton correct!" else "prediction wrong..."

    putStrLn "challenge 12:"
    doChallenge12

    putStrLn "challenge 13:"
    doChallenge13

    putStrLn "done"



