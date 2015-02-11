
module Set2
( pkcs7
) where

import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified Data.Map as Map
import Control.Monad
import Data.List
import Data.Int (Int64)
import Data.Word (Word8)
import Crypto.Cipher.AES
import System.Random
import Debug.Trace

import Set1

-- feels like procedural programming..
pkcs7 :: Int64 -> B.ByteString -> B.ByteString
pkcs7 blockSize x =
    let
        tmp = blockSize - mod (B.length x) blockSize
        padCount = if tmp == 0 then blockSize else tmp
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

encOracle :: AES -> Bool -> B.ByteString -> IO B.ByteString
encOracle key isCbc pt = do
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

createPtCtMap :: AES -> B.ByteString -> Map.Map B.ByteString B.ByteString
createPtCtMap key xs =
    Map.fromList $ map (\x -> (x, myEncryptECB key x)) (map (B.snoc xs) [0..255])

doChallenge12 :: IO ()
doChallenge12 = do
    unkText <- fmap (base64ToByteString . concat . lines) (readFile "12.txt")
    key <- genKey

    putStr "block size: "
    let blockSize = fmap (fromIntegral . (+1)) (findBlockSize key unkText)
    putStrLn $ show $ blockSize

    let ecbOracle k pt = fmap (\x -> myEncryptECB k $ B.append pt (pkcs7 x unkText)) blockSize

    putStr "is ECB: "
    putStrLn $ show $ fmap byteStringHasRepeat $ ecbOracle key (B.replicate 64 12)

    let breakEcbSimple ctr pre =
        let preMap = createPtCtMap key pre
            solvedBlock = Map.lookup (B.head $ ecbOracle key pre) preMay
        in if ctr == 0 then pre else breakEcbSimple (B.tail solvedBlock) (ctr-1)

    putStrLn $ show $ fmap (\x -> breakEcbSimple x (B.replicate (x-1) 'A')) blockSize


main = do
    print "challenge 9:"
    let res9 = pkcs7 20 (C8.pack "YELLOW SUBMARINE")
    print $ res9
    print $ B.unpack res9

    print "challenge 10:"
    print $ testCBC
    ct10 <- fmap (base64ToByteString . concat . lines) (readFile "10.txt")
    let key10 = initAES $ B.toStrict $ C8.pack "YELLOW SUBMARINE"
    let iv10 = C8.pack $ "0000000000000000"
    let pt10 = C8.unpack $ myDecryptCBC key10 iv10 ct10
    putStr pt10

    print "challenge 11:"
    isCbc <- getStdRandom random
    ct11 <- genKey >>= \key -> encOracle key isCbc (C8.pack pt10) -- TODO need randomly generate plain text
    print $ if isCbc /= (byteStringHasRepeat ct11)
                then "prediciton correct!" else "prediction wrong..."

    print "challenge 12:"
    doChallenge12

    print "done"



