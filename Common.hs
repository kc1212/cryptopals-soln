
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
import Data.List
import System.Random
import Control.Monad (liftM)
import Crypto.Cipher.AES
import Data.Numbers.Primes (primes)

import qualified MersenneTwister as MT

-- utils ----------------------------------------------------------------------
type Bs = B.ByteString

decodeHexStr :: String -> Bs
decodeHexStr x =
    let decodedStr = B16.decode $ C8.pack x
    in if C8.null $ snd decodedStr
        then fst decodedStr
        else error "decoding hex failed"

hexToBase64 :: String -> String
hexToBase64 x = C8.unpack $ B64.encode $ decodeHexStr x

byteByteXor :: Bs -> Bs -> Bs
byteByteXor a b = B.pack $ B.zipWith xor a b

bbXor :: Bs -> Bs -> Bs
bbXor = byteByteXor

rightXor :: Bs -> Bs -> Bs
rightXor a b =
    let (smaller,bigger) = if B.length a < B.length b then (a,b) else (b,a)
        smaller' = B.append (B.replicate (abs $ B.length a - B.length b) 0) smaller
    in B.pack $ B.zipWith xor smaller' bigger

hexByteXor :: String -> Bs -> Bs
hexByteXor a b = byteByteXor (decodeHexStr a) b

hexHexXor :: String -> String -> Bs
hexHexXor a b = byteByteXor (decodeHexStr a) (decodeHexStr b)

toChunksN :: Int64 -> Bs -> [Bs]
toChunksN n xs
    | n <= 0 = error "n must be greater than zero"
    | B.length xs == 0 = []
    | otherwise =
        let (a, b) = B.splitAt n xs
        in a : toChunksN n b

base64ToByteString :: String -> Bs
base64ToByteString str = rightOrError $ B64.decode $ C8.pack str

same :: Eq a => [a] -> Bool
same []     = error "same: empty list in same"
same [x]    = error "same: one item in list"
same (x:xs) = all (==x) xs

-- feels like procedural programming..
pkcs7 :: Int64 -> Bs -> Bs
pkcs7 bs x =
    let
        tmp = bs - mod (B.length x) bs
        padCount = if tmp == 0 then bs else tmp
    in
        B.append x (B.replicate padCount (fromIntegral padCount))

pkcs7aes :: Bs -> Bs
pkcs7aes = pkcs7 aesBs

validPkcs7 :: Bs -> Maybe Bs
validPkcs7 inp =
    let n = B.last inp
        (bytes,pad) = B.splitAt (B.length inp - fromIntegral n) inp
    in if n == 0 then Nothing -- last byte cannot end with zero
        else if B.all (==n) pad && mod (B.length inp) aesBs == 0
        then Just bytes
        else Nothing

endWith :: Bs -> Bs -> Bool
endWith inp target = target == B.drop (B.length inp - B.length target) inp

rightOrError :: Either String b -> b
rightOrError (Left a)  = error a
rightOrError (Right b) = b

-- TODO possibly take RandomGen as input?
genBytes :: Int -> IO Bs
genBytes n = do
    gen <- newStdGen
    return $ B.pack $ take n $ randoms gen

genKey :: IO AES
genKey = liftM (initAES . B.toStrict) (genBytes 16)

isPrintAndAscii :: Char -> Bool
isPrintAndAscii c = isPrint c && isAscii c

randomChoice :: [a] -> IO a
randomChoice xs =
    newStdGen >>= \gen -> return $ xs !! (head $ randomRs (0,length xs - 1) gen)

toSafeString :: String -> String
toSafeString inp = map (\x -> if isPrint x && isPrint x then x else '_') inp

takeNthAesChunk :: Int -> Bs -> Bs
takeNthAesChunk n xs = toChunksN aesBs xs !! n

discreteLog :: Integer -> Integer
discreteLog =
    let runner ctr inp = if 2^ctr == inp then ctr
        else if 2^ctr > inp then error "no result"
        else runner (ctr+1) inp
    in runner 0

runPowm :: Integer -> Integer -> Integer -> Integer -> Integer
runPowm b 0 m r = r
runPowm b e m r | e `mod` 2 == 1 = runPowm (b * b `mod` m) (e `div` 2) m (r * b `mod` m)
runPowm b e m r = runPowm (b * b `mod` m) (e `div` 2) m r

powm :: Integer -> Integer -> Integer -> Integer
powm b e m = runPowm b e m 1

-- crypto ---------------------------------------------------------------------
aesBs :: Int64
aesBs = 16

ctrBs :: Int64
ctrBs = 8

errBlockSize :: a
errBlockSize = error "wrong block size, TODO add information..."

myEncryptECB :: AES -> Bs -> Bs
myEncryptECB aes x =
    B.fromStrict $ encryptECB aes (B.toStrict x)

myDecryptECB :: AES -> Bs -> Bs
myDecryptECB aes x =
    B.fromStrict $ decryptECB aes (B.toStrict x)

-- note this includes padding
myEncryptCBC :: AES -> Bs -> Bs -> Bs
myEncryptCBC aes iv pt
    | B.length iv == aesBs =
        B.concat $ tail $ scanl (\x y -> myEncryptECB aes (byteByteXor x y)) iv ptChunks
    | otherwise = errBlockSize
    where ptChunks = toChunksN aesBs (pkcs7aes pt)

myDecryptCBC :: AES -> Bs -> Bs -> Bs
myDecryptCBC aes iv ct
    | B.length iv == aesBs =
        B.concat $ map (\(x,y) -> byteByteXor y (myDecryptECB aes x)) ctPairs
    | otherwise = errBlockSize
    where
        ctChunks = toChunksN aesBs ct
        ctPairs = zip ctChunks (iv : init ctChunks)

myCTR :: AES -> Word64 -> Word64 -> Bs -> Bs
myCTR key nonce ctr t =
    let ts = toChunksN aesBs t
        toBS = runPut . putWord64le
        ctrs = map (+ctr) [0..fromIntegral $ length ts - 1]
        pairs = zip ts $ map (B.append . toBS $ nonce) (map toBS ctrs)
    in B.concat $ map (\(t,nctr) -> myEncryptECB key nctr `byteByteXor` t) pairs
    --                                                 left aligned xor (le)

-- here we're using 16 bit seed (key) as requested by the question
-- but MT19937 actually takes 32 bit seed
myStreamCipher :: Word16 -> Bs -> Bs
myStreamCipher key t =
    let keyStream = MT.bytestringFromSeed (fromIntegral key) (B.length t)
    in byteByteXor keyStream t

myEditCTR :: AES -> Word64 -> Word64 -> Bs -> Word64 -> Bs -> Bs
myEditCTR key nonce ctr ct offset pt =
    let cts@(front,back) = splitAt (fromIntegral offset) (toChunksN aesBs ct)
        newCt = myCTR key nonce (ctr+offset) pt
    in if B.length pt == 16 || fromIntegral offset >= div (B.length ct) aesBs
        then B.concat (front ++ [newCt] ++ tail back)
        else error "bad input parameter"

-- fake cookie ----------------------------------------------------------------
prepUserData :: (Bs -> Bs) -> Bs -> String -> Bs -> Bs
prepUserData enc front rawInp back =
    let inp = C8.pack $ delete '&' $ delete '=' rawInp
    in enc (pkcs7 aesBs (B.append front $ B.append inp back))

checkUserData :: (Bs -> Bs) -> Bs -> Bool
checkUserData dec ct =
    let pt = fmap C8.unpack (validPkcs7 $ dec ct)
        res = fmap (isInfixOf ";admin=true;") pt
    in case res of
        Nothing -> error "padding error"
        Just True -> True
        Just False -> False

-- RSA related stuff ----------------------------------------------------------
type PubKey = Integer
type SecKey = (Integer, Integer)

genRsaKeys :: IO (PubKey, SecKey)
genRsaKeys = do
    let randRange = (0, 100000) -- index for primes
    g0 <- newStdGen
    let (r1,g1) = randomR randRange g0
    let (r2,g2) = randomR randRange g1
    let (r3,_)  = randomR randRange g2

    let p = primes !! r1 -- take r1'th prime number
    let q = primes !! r2 -- and r2'th
    let n = p * q

    let phi = (p - 1) * (q - 1)
    let ringz = filter ((1==) . gcd phi) [2..phi - 1]
    let e = ringz !! r3 -- unlikely for ringz to be shorter than r3
    let d = modInv e phi

    return (d, (e, n))


gcdExt a 0 = (1, 0, a)
gcdExt a b = let (q, r) = a `quotRem` b
                 (s, t, g) = gcdExt b r
             in (t, s - q * t, g)


modInv a m = let (i, _, g) = gcdExt a m
             in if g == 1 then mkPos i else error "couldn't find modInv"
  where mkPos x = if x < 0 then x + m else x


