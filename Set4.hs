
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import Crypto.Cipher.AES

import Common

doChallenge25 = do
    let keyOld = initAES $ B.toStrict $ C8.pack "YELLOW SUBMARINE"
    pt <- fmap (myDecryptECB keyOld . base64ToByteString . concat . lines) (readFile "25.txt")

    key <- genKey
    let nonce = 123
    let ctr = 456
    let ct = myCTR key nonce ctr pt
    let editCTR = myEditCTR key nonce ctr ct
    let myPt = C8.pack "AAAAAAAAAAAAAAAA"

    let keyStream = B.concat $
                        map (\x -> myPt `byteByteXor` (takeNthAesChunk x $ editCTR (fromIntegral x) myPt))
                        [0..length (toChunksN aesBs ct) - 1]
    let res = C8.unpack $ byteByteXor keyStream ct

    putStrLn $ res


main = do
    putStrLn "challenge 25:"
    doChallenge25
    putStrLn ""


