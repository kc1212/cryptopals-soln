
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import Data.ByteString.Internal (w2c)
import Control.Applicative
import Crypto.Cipher.AES
import Data.List
import Data.Bits
import Data.Word (Word8, Word32)
import Data.Char
import System.Random
import Data.Time.Clock.POSIX

import Common
import qualified MersenneTwister as MT

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

goodHistogram2 :: Bool -> String -> Bool
goodHistogram2 isFirst str =
    let
        len = fromIntegral $ length str
        allAscii = all isAscii str
        myIsPunctuation x = isPunctuation x && all (x /=) "#$^&*_+=-][}{@\\|/<>~\DEL"
        specialCheck = (fromIntegral $ length $ filter (\x -> isAlphaNum x || myIsPunctuation x || isSpace x) str) > (0.95 * len)
        checkRule = if isFirst then (\x -> x=='t' || x=='a' || x=='s') else (\x -> x=='a' || x=='e' || x=='o' || x=='t')
        checkPercent = if isFirst then 0.30 else 0.20
        freqCheck = (fromIntegral $ length $ filter checkRule str) > (checkPercent * len)
    in
        allAscii && freqCheck && specialCheck

findTextAfterXor :: Bool -> [Word8] -> [Word8] -> [Word8]
findTextAfterXor isFirst _ [] = []
findTextAfterXor isFirst bs (x:xs) =
    case goodHistogram2 isFirst (map (w2c . xor x) bs) of
        True -> x : findTextAfterXor isFirst bs xs
        _    -> findTextAfterXor isFirst bs xs

-- semi-automated, the remaining characters should be guessable
-- can be improved if the first few characters are computed with a different rule
-- TODO I used the method described in challenge 20 too early, this challenge uses a simpler method
doChallenge19 = do
    key <- genKey
    let enc = myCTR key 0 0
    cts <- lines <$> (readFile "19.txt") >>= return . map (enc . base64ToByteString)

    let cts' = B.transpose cts
    let resHead = (\x -> findTextAfterXor True (B.unpack x) [0..255]) (head cts')
    let resRest = map (\x -> findTextAfterXor False (B.unpack x) [0..255]) (tail cts')
    let res = B.pack $ map (\x -> if x == [] then 0 else head x) (resHead:resRest)

    putStrLn $ show $ length $ filter ((==1) . length) (resHead:resRest)
    mapM (putStrLn . toSafeString . C8.unpack . byteByteXor res) cts

doChallenge20 = do
    key <- genKey
    let enc = myCTR key 0 0
    cts <- lines <$> (readFile "20.txt") >>= return . map (enc . base64ToByteString)
    let truncatedCts = map (B.take (last $ map B.length cts)) cts

    let cts' = B.transpose truncatedCts
    let resHead = (\x -> findTextAfterXor True (B.unpack x) [0..255]) (head cts')
    let resRest = map (\x -> findTextAfterXor False (B.unpack x) [0..255]) (tail cts')
    let res = B.pack $ map (\x -> if x == [] then 0 else head x) (resHead:resRest)

    putStrLn $ show $ length $ filter ((==1) . length) (resHead:resRest)
    mapM (putStrLn . toSafeString . C8.unpack . byteByteXor res) cts

doChallenge21 = do
    seed <- fmap round getPOSIXTime
    putStrLn $ show $ MT.wordFromSeed seed

-- this challenge is a bit slow, most likely due to my MT19937 implementation
doChallenge22 = do
    gen1 <- newStdGen
    gen2 <- newStdGen
    unkSeed <- (fmap round getPOSIXTime :: IO Word32) >>= \x -> return (x + head (randomRs (40,1000) gen1))

    let randomNumber = MT.wordFromSeed unkSeed
    let timeNow = unkSeed + head (randomRs (40,1000) gen2)

    let res = head $ filter
                        (\(_,rand) -> randomNumber==rand)
                        (map (\x -> (x, MT.wordFromSeed x)) [timeNow - x | x <- [0..]])
    putStrLn $ show res
    putStrLn $ show $ fst res == unkSeed

untemperMT :: Word32 -> Word32
untemperMT inp =
    let y1 = inp `xor` (shiftR inp 18)
        y2a = y1 `xor` 0xefc60000                       -- bit 0..14
        y2b = y2a `xor` (shiftL y2a 15 .&. 0xefc60000)  -- bit 15..29
        y2c = y2b `xor` (shiftL y2b 15 .&. 0xefc60000)  -- bit 30..31
        y2 = y2c .&. 0xC0000000 `xor` y2b .&. 0x3FFF8000 `xor` y2a .&. 0x00007FFF
        y3a = y2 `xor` 0x9d2c5680                       -- bit 0..6
        y3b = y3a `xor` (shiftL y3a 7 .&. 0x9d2c5680)   -- bit 7..13
        y3c = y3b `xor` (shiftL y3b 7 .&. 0x9d2c5680)   -- bit 14..20
        y3d = y3c `xor` (shiftL y3c 7 .&. 0x9d2c5680)   -- bit 21..27
        y3e = y3d `xor` (shiftL y3d 7 .&. 0x9d2c5680)   -- bit 28..31
        y3 = y3e .&. 0xF0000000 `xor` y3d .&. 0x0FE00000 `xor` y3c .&. 0x001FC000 `xor`
             y3b .&. 0x00003F80 `xor` y3a .&. 0x0000007F
        y4a = y3 `xor` (shiftR y3 11)                   -- bit 21..31
        y4b = y4a `xor` (shiftR y4a 11)                 -- bit 10..20
        y4c = y4b `xor` (shiftR y4b 11)                 -- bit 0..9
        y4 = y4a .&. 0xFFE00000 `xor` y4b .&. 0x001FFC00 `xor` y4a .&. 0x000003FF
    in y4


doChallenge23 = do
    gen <- newStdGen
    seed <- (fmap round getPOSIXTime :: IO Word32) >>= \x -> return (x + head (randomRs (40,1000) gen))

    let randomList = MT.listFromSeed seed 624
    let internalState = map untemperMT randomList
    putStrLn $ show internalState
    putStrLn ""
    putStrLn $ show $ snd (MT.initGenerator seed)
    putStrLn ""
    putStrLn $ show $ MT.generateNumber $ snd (MT.initGenerator seed)


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

    putStrLn "challenge 20:"
    doChallenge20
    putStrLn ""

    putStrLn "challenge 21:"
    doChallenge21
    putStrLn ""

    putStrLn "challenge 22:"
    doChallenge22
    putStrLn ""

    putStrLn "done"



