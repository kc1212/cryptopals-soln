
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import Data.ByteString.Internal (w2c)
import Control.Applicative
import Crypto.Cipher.AES
import Data.List
import Data.Bits (xor)
import Data.Word (Word8)
import System.Random

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
        else error $ "something went wrong. \nres: " ++ show res ++ "\ninp: " ++ show inp

doChallenge17 = do
    key <- genKey
    iv  <- genBytes 16
    gen <- newStdGen

    pts <- lines <$> (readFile "17.txt") >>= return . map (C8.pack)
    let pt = pts !! (head $ randomRs (0, length pts - 1) gen)
    let ct = [iv] ++ toChunksN aesBs (encPaddingOracle key iv pt)
    let cts = drop 2 $ inits ct
    let res = iHateMaybe $ validPkcs7 $ B.concat $ map (crackOneBlock (C8.pack "") (decPaddingOracle key iv)) cts

    putStrLn $ show res
    putStrLn $ show $ res == pt


doChallenge18 = do
    let key = initAES $ B.toStrict $ C8.pack "YELLOW SUBMARINE"
    let ct = base64ToByteString "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

    -- nonce and ctr both zero
    putStrLn $ show $ myCTR key 0 0 ct

    ctrR <- newStdGen >>= return . head . randoms
    nonceR <- newStdGen >>= return . head . randoms
    putStrLn $ show $ ct == myCTR key nonceR ctrR (myCTR key nonceR ctrR ct)

findAsciiAfterXor :: [Word8] -> [Word8] -> [Word8]
findAsciiAfterXor _ [] = []
findAsciiAfterXor bs (x:xs) =
    case all (\a -> isPrintAndAscii $ w2c (a `xor` x)) bs of
        True -> x : findAsciiAfterXor bs xs
        _    -> findAsciiAfterXor bs xs

doChallenge19 = do
    key <- genKey
    let enc = myCTR key 0 0

    cts <- lines <$> (readFile "19.txt") >>= return . map (enc . base64ToByteString)
    let cts' = B.transpose cts
    let res = map (\x -> findAsciiAfterXor (B.unpack x) [0..255]) cts'

    putStrLn $ show $ map length res

main = do
    putStrLn "challenge 17:"
    doChallenge17
    putStrLn ""

    putStrLn "challenge 18:"
    doChallenge18
    putStrLn ""

    putStrLn "challenge 19:"
    doChallenge19
    putStrLn ""

    putStrLn "done"



