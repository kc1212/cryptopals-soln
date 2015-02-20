
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

doChallenge17 = do
    key <- genKey
    iv  <- genBytes 16

    pts <- lines <$> (readFile "17.txt") >>= return . map (C8.pack)
    let pt = pts !! 0 -- TODO only attack one for now
    let ct = toChunksN aesBs (encPaddingOracle key iv pt)

    let tries = [0..255]
    let paddings = map (\x -> B.replicate x (fromIntegral x)) [1..aesBs]

    -- TODO try to decrypt last block first, then refactor the code to do all blocks
    let ctBlocks = length ct
    let modBlock b x =
            let b' = B.append (B.replicate (aesBs - B.length x) 0) x
            in byteByteXor b' b

    putStrLn $ show paddings

main = do
    doChallenge17
    putStrLn "done"



