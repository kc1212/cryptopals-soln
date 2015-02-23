
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import Control.Applicative
import Crypto.Cipher.AES

import Common

encPaddingOracle :: AES -> B.ByteString -> B.ByteString -> B.ByteString
encPaddingOracle key iv inp = myEncryptCBC key iv (pkcs7aes inp)

decPaddingOracle :: AES -> B.ByteString -> B.ByteString -> Bool
decPaddingOracle key iv ct =
    case validPkcs7 (myDecryptCBC key iv ct) of
        Nothing -> False
        _       -> True

-- right align xor a block (b) with some bytes (x)
modBlock :: B.ByteString -> B.ByteString -> B.ByteString
modBlock b x =
    let lenx = B.length x
        b' = B.append (B.replicate (aesBs - lenx) 0) x
    in case lenx > 16 || lenx < 1 of
        True  -> error $ "'x' has bad length: " ++ show (lenx)
        _     -> byteByteXor b' b

allPaddings :: [B.ByteString]
allPaddings = map (\x -> B.replicate x (fromIntegral x)) [1..aesBs]

crackOneBlock :: B.ByteString -> (B.ByteString -> Bool) -> [B.ByteString] -> B.ByteString
crackOneBlock inp oracle ct =
    let l = B.length inp
        (ct1,ct2) = splitAt (length ct - 2) ct
        tryx x = modBlock (B.replicate (l+1) (fromIntegral $ l+1)) (B.cons x inp)
        blox x = ct1 ++ [x `byteByteXor` head ct2] ++ tail ct2
        res = filter (\(_,x) -> x)
                (map ( \x -> (x, (oracle $ B.concat $ blox $ tryx x)) ) [0..255])
    in if B.length inp == aesBs then inp
        else if length res == 1 then crackOneBlock (B.cons (fst $ head res) inp) oracle ct
        else error "something went wrong!"

doChallenge17 = do
    key <- genKey
    iv  <- genBytes 16

    pts <- lines <$> (readFile "17.txt") >>= return . map (C8.pack)
    let pt = pts !! 0 -- TODO only attack one for now
    let ct = toChunksN aesBs (encPaddingOracle key iv pt)

    putStrLn $ show $ crackOneBlock (C8.pack "") (decPaddingOracle key iv) ct

main = do
    doChallenge17
    putStrLn "done"



