
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C8
import qualified Data.ByteString.Base64.Lazy as B64
import qualified Data.ByteString.Base16.Lazy as B16
import System.Random
import Control.Applicative
import Common

randPosInteger :: IO Integer
randPosInteger =
    head <$> filter (>1) <$> randoms <$> newStdGen

bsToInteger :: Bs -> Integer
bsToInteger bs =
    foldl (\prev v -> (prev * 256) + (fromIntegral v)) 0 (B.unpack bs)

doChallenge33 = do
    let pStr = filter (/='\n') $ unlines [
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024",
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd",
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec",
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f",
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361",
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552",
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff",
            "fffffffffffff" ]
    let p = bsToInteger $ decodeHexStr pStr
    let g = 2

    a <- flip mod 37 <$> randPosInteger
    let bigA = (g ^ a) `mod` p

    b <- flip mod 37 <$> randPosInteger
    let bigB = (g ^ b) `mod` p

    let sa = (bigB ^ a) `mod` p
    let sb = (bigA ^ b) `mod` p

    putStrLn $ show sa
    putStrLn $ show $ sa == sb


main = do
    putStrLn "challenge 33 simple:"
    doChallenge33
    putStrLn ""

