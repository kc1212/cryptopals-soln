
module Set2
( pkcs7
) where

import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import Data.Int (Int64)
import Crypto.Cipher.AES

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

-- the to/from strict conversion is a bit annoying
plainAES :: Bool -> AES -> B.ByteString -> B.ByteString
plainAES enc aes x
    | B.length x == aesBlockSize = B.fromStrict $ f aes (B.toStrict x)
    | otherwise = errBlockSize
    where f = if enc then encryptECB else decryptECB

myEncryptCBC :: AES -> B.ByteString -> B.ByteString -> B.ByteString
myEncryptCBC aes iv pt
    | B.length iv == aesBlockSize =
        B.concat $ tail $ scanl (\x y -> plainAES True aes (byteByteXor x y)) iv ptChunks
    | otherwise = errBlockSize
    where ptChunks = toChunksN 16 (pkcs7 aesBlockSize pt)

myDecryptCBC :: AES -> B.ByteString -> B.ByteString -> B.ByteString
myDecryptCBC aes iv ct
    | B.length iv == aesBlockSize =
        B.concat $ map (\(x,y) -> byteByteXor y (plainAES False aes x)) ctPairs
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

main = do
    print "challenge 9:"
    let res1 = pkcs7 20 (C8.pack "YELLOW SUBMARINE")
    print $ res1
    print $ B.unpack res1

    print "challenge 10:"
    print $ testCBC
    contentRaw2 <- readFile "10.txt"
    let ct2 = base64ToByteString $ concat $ lines contentRaw2
    let key2 = initAES $ B.toStrict $ C8.pack "YELLOW SUBMARINE"
    let iv2 = C8.pack $ "0000000000000000"
    print $ myDecryptCBC key2 iv2 ct2


    print "done"



