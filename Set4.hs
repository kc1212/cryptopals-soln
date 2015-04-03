
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified Data.ByteString.Base16.Lazy as B16
import System.Random
import Data.Char
import Data.Binary
import Crypto.Cipher.AES
import Control.Applicative

import Common
import ShaOne


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


doChallenge26 = do
    key <- genKey

    let s1 = C8.pack "comment1=cooking%20MCs;userdata="
    let s2 = C8.pack ";comment2=%20like%20a%20pound%20of%20bacon"
    --                 0       8       16
    --                 ;admin=true;AAA=

    -- extra length needed to fill s1 to block boundry
    let extraLen = let l = mod (B.length s1) aesBs in if l == 0 then 0 else aesBs - l
    let pt = C8.unpack $ B.replicate (aesBs + extraLen) 65
    let ct = prepUserData (myCTR key 1 2) s1 pt s2

    let loc = B.length s1 + extraLen + aesBs
    let ct2 = byteByteXor (B.take aesBs s2) (C8.pack ";admin=true;AAA=")
    let ctzeros = B.append
                    (B.append (B.replicate loc 0) ct2)
                    (B.replicate (B.length ct - loc - aesBs) 0)
    let ct' = byteByteXor ctzeros ct

    putStrLn $ show $ if (checkUserData (myCTR key 1 2) ct' == True) then "success!" else "fail..."

-- this is a bit weird because Just something will represent failure
checkHighAscii :: Bs -> (Maybe Bs)
checkHighAscii xs =
    case all isAscii (C8.unpack xs) of
        True -> Nothing
        False -> Just xs

doChallenge27 = do
    iv <- genBytes 16
    let key = initAES $ B.toStrict iv

    let pt  = B.concat (B.replicate aesBs 65 : B.replicate aesBs 66 : B.replicate aesBs 67 : [])
    let ct  = myEncryptCBC key iv pt -- padding will be added to the end
    let ct' = let (a:b:c) = toChunksN aesBs ct
                in B.concat $ a : B.replicate aesBs 0 : a : []
    let key' =
            case checkHighAscii (myDecryptCBC key iv ct') of
                Nothing -> Nothing
                Just x  -> let pts = toChunksN aesBs x in Just (byteByteXor (head pts) (pts !! 2))

    putStrLn $ show $ fmap (iv==) key'

doChallenge28 = do
    key <- genBytes 16
    let msg = C8.pack "my message"
    let digest = shaOne (B.append key msg)

    let msg2 = C8.pack "my messaga"
    let digest2 = shaOne (B.append key msg2)

    putStrLn $ show $ digest2 /= digest

    let test1 = C8.pack "The quick brown fox jumps over the lazy dog"
    let test2 = C8.pack "The quick brown fox jumps over the lazy cog"
    let test3 = C8.pack ""
    putStrLn $ show $ shaOneB64 test1 == "L9ThxnotKPzthJ7hu3bnORuT6xI="
                   && shaOneHex test2 == "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"
                   && shaOneHex test3 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

shaOneRegisters :: Bs -> HTuple
shaOneRegisters xs =
    let xl = map decode (toChunksN 4 xs)
    in case length xl of
        5 -> (xl!!0, xl!!1, xl!!2, xl!!3, xl!!4)
        _ -> error "invalid input"

doChallenge29 = do
    key <- (head . randomRs (5,1000) <$> newStdGen) >>= genBytes
    let msg1  = C8.pack "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    let hash1 = shaOne $ key `B.append` msg1
    let state = shaOneRegisters hash1

    let forge = C8.pack ";admin=true"
    let hash2 fakeKey = let (h0,h1,h2,h3,h4) = shaOneOnChunkS state (preProcessForged forge forgedLen)
                            forgedLen = B.length (B.concat $ preProcess $ fakeKey `B.append` msg1) + B.length forge
                in B.concat $ map encode (h0:h1:h2:h3:h4:[])
    let msg2  = B.concat (preProcess (key `B.append` msg1)) `B.append` forge

    let res = head . filter (== shaOne msg2) . map hash2 $ map (\x -> B.replicate x 0) [0..2000]
    putStrLn $ show $ "forged hash: " ++ C8.unpack (B16.encode res)


main = do
    putStrLn "challenge 25:"
    doChallenge25
    putStrLn ""

    putStrLn "challenge 26:"
    doChallenge26
    putStrLn ""

    putStrLn "challenge 27:"
    doChallenge27
    putStrLn ""

    putStrLn "challenge 28:"
    doChallenge28
    putStrLn ""

    putStrLn "challenge 29:"
    doChallenge29
    putStrLn ""


