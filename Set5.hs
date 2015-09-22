
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified Data.ByteString.Base64.Lazy as B64
import qualified Data.ByteString.Base16.Lazy as B16
import System.Random
import Data.Binary
import Control.Applicative
import Crypto.Cipher.AES
import Common
import ShaOne

randPosInteger :: Integer -> IO Integer
randPosInteger p =
    head <$> filter (>1) <$> randomRs (0, p) <$> newStdGen

bsToInteger :: Bs -> Integer
bsToInteger bs =
    foldl (\prev v -> (prev * 256) + (fromIntegral v)) 0 (B.unpack bs)

globalP :: Integer
globalP = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

globalG :: Integer
globalG = 2

dhEnc :: Integer -> Bs -> IO (Bs, Bs)
dhEnc shared msg = do
    iv <- genBytes 16
    let key = initAES . B.toStrict . B.take 16 . shaOne . encode $ shared
    return (myEncryptCBC key iv msg, iv)

dhDec :: Integer -> (Bs, Bs) -> Bs
dhDec shared (msg, iv) =
    myDecryptCBC key iv msg
    where key = initAES . B.toStrict . B.take 16 . shaOne . encode $ shared

nistPrime :: Integer
nistPrime = 2 ^ 255 - 19

doChallenge33 = do
    let p = globalP
    let g = globalG

    a <- randPosInteger p
    let bigA = powm g a p

    b <- randPosInteger p
    let bigB = powm g b p

    let sa = powm bigB a p
    let sb = powm bigA b p

    putStrLn $ show sa
    putStrLn $ show $ sa == sb


doChallenge34 = do
    let p = globalP
    let g = globalG

    -- forge bigA as bigA', and send it to B
    a <- randPosInteger p
    let bigA' = p

    -- forge bigB as bigB', and send it to A
    b <- randPosInteger p
    let bigB' = p

    -- sa and sb should both be zero
    let sa = powm bigB' a p
    let sb = powm bigA' b p

    let msg = C8.pack "ohlala"
    msga <- dhEnc sa msg
    msgb <- dhEnc sb (dhDec sb msga)

    let key = 0
    -- decrypt the message as attacker
    putStrLn $ show $
        B.take 5 (dhDec key msga) == B.take 5 (dhDec key msgb)


doChallenge35 y x = do
    let p = y
    let g' = if x == 1 || x == p || x == (p-1) then x else error "invalid x"

    a <- randPosInteger p
    let bigA' = powm g' a p

    b <- randPosInteger p
    let bigB' = powm g' b p

    -- sa and sb will be predictable when using forged g
    let sa = powm bigB' a p
    let sb = powm bigA' b p

    let msg = C8.pack "ohlala"
    msga <- dhEnc sa msg
    msgb <- dhEnc sb (dhDec sb msga)

    -- decrypt the message as attacker
    let key =
            if x == 1
                then 1
            else if x == p
                then 0
            else if x == (p - 1) && bigA' == (p - 1) && bigB' == (p - 1)
                then p - 1
            else if x == (p - 1) -- bigA' == 1 || bigB' == 1
                then 1
            else
                error "error..."

    putStrLn $ show $
        B.take 5 (dhDec key msga) == B.take 5 (dhDec key msgb)

doChallenge36 = do
    let g = globalG
    let k = 3
    let email = "myname@domain.me" -- not used?
    let pw = "Password1"

    -- server
    salt <- genBytes 32
    let xs = decode . shaOne $ B.append salt (C8.pack pw) :: Integer
    let v = powm g xs nistPrime

    -- client -> server
    a <- randPosInteger nistPrime
    let bigA = powm g a nistPrime

    -- server -> client
    b <- randPosInteger nistPrime
    let bigB = k * v + powm g b nistPrime

    -- both compute uH
    let u = decode . shaOne . B.append (encode bigA) $ (encode bigB) :: Integer

    -- client
    let xc = decode . shaOne . B.append salt $ C8.pack pw :: Integer
    let bigSc = powm (bigB - k * g ^ xc) (a + u * xc) nistPrime
    let bigKc = shaOne (encode bigSc)

    -- server
    let bigSs = powm (bigA * v ^ u) b nistPrime
    let bigKs = shaOne (encode bigSs)

    -- send hmac from client to server
    let hmacc = shaOneHmac bigKc salt

    -- -- verify hmac at server
    let hmacs = shaOneHmac bigKs salt

    putStrLn . C8.unpack . encode $ bigSc
    putStrLn "getting not enough bytes error..."



main = do
    putStrLn "challenge 33:"
    doChallenge33
    putStrLn ""

    putStrLn "challenge 34:"
    doChallenge34
    putStrLn ""

    putStrLn "challenge 35:"
    doChallenge35 globalP 1
    doChallenge35 globalP globalP
    doChallenge35 globalP (globalP - 1)
    putStrLn ""

    putStrLn "challenge 36:"
    doChallenge36

