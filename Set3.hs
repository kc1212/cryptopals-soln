
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import Control.Applicative
import Crypto.Cipher.AES

import Common

encPaddingOracle :: AES -> B.ByteString -> B.ByteString -> B.ByteString
encPaddingOracle key iv inp = myEncryptCBC key iv inp

decPaddingOracle :: AES -> B.ByteString -> B.ByteString -> (Bool,B.ByteString)
decPaddingOracle key iv ct =
    let pt = myDecryptCBC key iv ct
    in case validPkcs7 pt of
        Nothing -> (False, pt)
        _       -> (True, pt)

allPaddings :: [B.ByteString]
allPaddings = map (\x -> B.replicate x (fromIntegral x)) [1..aesBs]

crackOneBlock :: B.ByteString -> (B.ByteString -> (Bool, B.ByteString)) -> [B.ByteString] -> B.ByteString
crackOneBlock inp oracle ct =
    let l = B.length inp
        (ct1,ct2) = splitAt (length ct - 2) ct
        padding = B.replicate (l+1) (fromIntegral $ l+1)
        newBlk x = rightXor padding (B.cons x inp)
        forgeCt x = ct1 ++ [rightXor x (head ct2)] ++ tail ct2
        res = filter (\(_,(x,pt)) -> x && endWith pt padding)
                (map (\x -> (x, oracle $ B.concat $ forgeCt $ newBlk x)) [0..255])
    in if B.length inp == aesBs then inp
        else if length res == 1 then crackOneBlock (B.cons (fst $ head res) inp) oracle ct
        else error $ "something went wrong. res: " ++ show res ++ ", inp: " ++ show inp

doChallenge17 = do
    key <- genKey
    iv  <- genBytes 16

    pts <- lines <$> (readFile "17.txt") >>= return . map (C8.pack)
    let pt = pts !! 0 -- TODO only attack one for now
    let ct = [iv] ++ toChunksN aesBs (encPaddingOracle key iv pt)

    putStrLn $ show $ crackOneBlock (C8.pack "") (decPaddingOracle key iv) ct

main = do
    doChallenge17
    putStrLn "done"



