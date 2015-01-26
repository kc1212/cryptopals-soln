
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
plainAES :: AES -> B.ByteString -> B.ByteString
plainAES aes x
    | B.length x == aesBlockSize = B.fromStrict $ encryptECB aes (B.toStrict x)
    | otherwise = errBlockSize

myEncryptCBC :: AES -> B.ByteString -> B.ByteString -> B.ByteString
myEncryptCBC aes iv pt
    | B.length iv == aesBlockSize =
        B.concat $ tail $ scanl (\x y -> plainAES aes (byteByteXor x y)) iv ptChunks
    | otherwise = errBlockSize
    where ptChunks = toChunksN 16 (pkcs7 aesBlockSize pt)

-- myDecryptCBC :: AES -> B.ByteString -> B.ByteString -> B.ByteString
-- myDecryptCBC aes iv ct
--     | B.length iv == aesBlockSize =
--         B.concat $ scanl (\x y -> byteByteXor x (plainAES aes y)) iv ctChunks
--     | otherwise = errBlockSize
--     where ctChunks = toChunksN 16 ct

main = do
    print "challenge 1:"
    let res1 = pkcs7 20 (C8.pack "YELLOW SUBMARINE")
    print $ res1
    print $ B.unpack res1

    print "challenge 2:"

    print "done"



