
module Common where

import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified Data.ByteString.Base64.Lazy as B64
import qualified Data.ByteString.Base16.Lazy as B16
import Data.Int (Int64)
import Data.Binary
import Data.Binary.Put
import Data.Bits
import Data.Char
import System.Random
import Crypto.Cipher.AES

import qualified MersenneTwister as MT

-- utils ----------------------------------------------------------------------
decodeHexStr :: String -> B.ByteString
decodeHexStr x =
    let decodedStr = B16.decode $ C8.pack x
    in if C8.null $ snd decodedStr
        then fst decodedStr
        else error "decoding hex failed"

hexToBase64 :: String -> String
hexToBase64 x = C8.unpack $ B64.encode $ decodeHexStr x

byteByteXor :: B.ByteString -> B.ByteString -> B.ByteString
byteByteXor a b = B.pack $ B.zipWith xor a b

rightXor :: B.ByteString -> B.ByteString -> B.ByteString
rightXor a b =
    let (smaller,bigger) = if B.length a < B.length b then (a,b) else (b,a)
        smaller' = B.append (B.replicate (abs $ B.length a - B.length b) 0) smaller
    in B.pack $ B.zipWith xor smaller' bigger

hexByteXor :: String -> B.ByteString -> B.ByteString
hexByteXor a b = byteByteXor (decodeHexStr a) b

hexHexXor :: String -> String -> B.ByteString
hexHexXor a b = byteByteXor (decodeHexStr a) (decodeHexStr b)

toChunksN :: Int64 -> B.ByteString -> [B.ByteString]
toChunksN n xs
    | n <= 0 = error "n must be greater than zero"
    | B.length xs == 0 = []
    | otherwise =
        let (a, b) = B.splitAt n xs
        in [a] ++ toChunksN n b

base64ToByteString :: String -> B.ByteString
base64ToByteString str = rightOrError $ B64.decode $ C8.pack str

same :: Eq a => [a] -> Bool
same []     = error "same: empty list in same"
same [x]    = error "same: one item in list"
same (x:xs) = all (==x) xs

-- feels like procedural programming..
pkcs7 :: Int64 -> B.ByteString -> B.ByteString
pkcs7 bs x =
    let
        tmp = bs - mod (B.length x) bs
        padCount = if tmp == 0 then bs else tmp
    in
        B.append x (B.replicate padCount (fromIntegral padCount))

pkcs7aes :: B.ByteString -> B.ByteString
pkcs7aes = pkcs7 aesBs

validPkcs7 :: B.ByteString -> Maybe B.ByteString
validPkcs7 inp =
    let n = B.last inp
        (bytes,pad) = B.splitAt (B.length inp - fromIntegral n) inp
    in if n == 0 then Nothing -- last byte cannot end with zero
        else if B.all (==n) pad && mod (B.length inp) aesBs == 0
        then Just bytes
        else Nothing

endWith :: B.ByteString -> B.ByteString -> Bool
endWith inp target = target == B.drop (B.length inp - B.length target) inp

iHateMaybe :: Maybe a -> a
iHateMaybe (Just a) = a
iHateMaybe Nothing = error "I loathe Nothing more!"

rightOrError :: Either String b -> b
rightOrError (Left a)  = error a
rightOrError (Right b) = b

-- TODO possibly take RandomGen as input?
genBytes :: Int -> IO B.ByteString
genBytes n = do
    gen <- newStdGen
    return $ B.pack $ take n $ randoms gen

genKey :: IO AES
genKey = genBytes 16 >>= return . initAES . B.toStrict

isPrintAndAscii :: Char -> Bool
isPrintAndAscii = \c -> isPrint c && isAscii c

randomChoice :: [a] -> IO a
randomChoice xs =
    newStdGen >>= \gen -> return $ xs !! (head $ randomRs (0,length xs - 1) gen)

toSafeString :: String -> String
toSafeString inp = map (\x -> if isPrint x && isPrint x then x else '_') inp

-- crypto ---------------------------------------------------------------------
aesBs :: Int64
aesBs = 16

ctrBs :: Int64
ctrBs = 8

errBlockSize :: a
errBlockSize = error "wrong block size, TODO add information..."

myEncryptECB :: AES -> B.ByteString -> B.ByteString
myEncryptECB aes x =
    B.fromStrict $ encryptECB aes (B.toStrict x)

myDecryptECB :: AES -> B.ByteString -> B.ByteString
myDecryptECB aes x =
    B.fromStrict $ decryptECB aes (B.toStrict x)

-- note this includes padding
myEncryptCBC :: AES -> B.ByteString -> B.ByteString -> B.ByteString
myEncryptCBC aes iv pt
    | B.length iv == aesBs =
        B.concat $ tail $ scanl (\x y -> myEncryptECB aes (byteByteXor x y)) iv ptChunks
    | otherwise = errBlockSize
    where ptChunks = toChunksN aesBs (pkcs7aes pt)

myDecryptCBC :: AES -> B.ByteString -> B.ByteString -> B.ByteString
myDecryptCBC aes iv ct
    | B.length iv == aesBs =
        B.concat $ map (\(x,y) -> byteByteXor y (myDecryptECB aes x)) ctPairs
    | otherwise = errBlockSize
    where
        ctChunks = toChunksN aesBs ct
        ctPairs = zip ctChunks (iv : init ctChunks)

myCTR :: AES -> Word64 -> Word64 -> B.ByteString -> B.ByteString
myCTR key nonce ctr t =
    let ts = toChunksN aesBs t
        toBS = runPut . putWord64le
        ctrs = map (+ctr) [0..fromIntegral $ length ts - 1]
        pairs = zip ts $ map (B.append . toBS $ nonce) (map toBS ctrs)
    in B.concat $ map (\(t,nctr) -> myEncryptECB key nctr `byteByteXor` t) pairs
    --                                                 left aligned xor (le)

-- here we're using 16 bit seed (key) as requested by the question
-- but MT19937 actually takes 32 bit seed
myStreamCipher :: Word16 -> B.ByteString -> B.ByteString
myStreamCipher key t =
    let keyStream = MT.bytestringFromSeed (fromIntegral key) (B.length t)
    in byteByteXor keyStream t


