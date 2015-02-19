
module Common where

import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import Data.Int (Int64)
import System.Random
import Crypto.Cipher.AES

aesBs :: Int64
aesBs = 16

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

validPkcs7 :: B.ByteString -> Maybe B.ByteString
validPkcs7 inp =
    let n = B.last inp
        (bytes,pad) = B.splitAt (B.length inp - fromIntegral n) inp
    in if B.all (==n) pad && mod (B.length inp) aesBs == 0
        then Just bytes
        else Nothing

iHateMaybe :: Maybe a -> a
iHateMaybe (Just a) = a
iHateMaybe Nothing = error "I loathe Nothing more!"

-- TODO possibly take RandomGen as input?
genBytes :: Int -> IO B.ByteString
genBytes n = do
    gen <- newStdGen
    return $ B.pack $ take n $ randoms gen

genKey :: IO AES
genKey = genBytes 16 >>= return . initAES . B.toStrict

