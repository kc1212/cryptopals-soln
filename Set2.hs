
module Set2
( pkcs7
) where

import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
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

encOracle :: B.ByteString -> Bool -> IO B.ByteString
encOracle pt isCbc = do
    before  <- getStdRandom (randomR (5,10)) >>= genBytes
    after   <- getStdRandom (randomR (5,10)) >>= genBytes
    iv      <- genBytes 16
    key     <- genKey
    let ptx = pkcs7 16 $ B.append before (B.append pt after)
    return $ if isCbc then myEncryptCBC key iv ptx else myEncryptECB key ptx

byteStringHasRepeat :: B.ByteString -> Bool
byteStringHasRepeat ct =
    let cts = toChunksN 16 ct
    in any ((>= 2) . length) (group $ sort cts)

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
    ct11 <- encOracle (C8.pack pt10) isCbc -- TODO need randomly generate plain text
    print $ if isCbc /= (byteStringHasRepeat ct11)
                then "prediciton correct!" else "prediction wrong..."

    print "done"



