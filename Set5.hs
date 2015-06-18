
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

    a <- randPosInteger p
    let bigA = powm g a p
    let bigA' = p

    b <- randPosInteger p
    let bigB = powm g b p
    let bigB' = p

    -- sa and sb should both be zero
    let sa = powm bigB' a p
    let sb = powm bigA' b p

    let msg = C8.pack "ohlala"
    msga <- dhEnc sa msg
    msgb <- dhEnc sb (dhDec sb msga)

    -- decrypt the message as attacker
    putStrLn $ show $ dhDec 0 msga
    putStrLn $ show $ dhDec 0 msgb


main = do
    putStrLn "challenge 33 simple:"
    doChallenge33
    putStrLn ""

    putStrLn "challenge 34 simple:"
    doChallenge34
    putStrLn ""


