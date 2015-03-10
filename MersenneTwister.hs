
-- import Data.Int (Int32)
import Data.Word (Word32)
import Data.Bits

mtSize = 624
mtMagic = 0x6c078965
upperMask = 0x80000000
lowerMask = 0x7fffffff
matrixA = 0x9908b0df
defaultSeed = 5489

initGenerator :: Word32 -> [Word32]
initGenerator seed = runInitGenerator 1 [seed]

generateNumber :: [Word32] -> [Word32]
generateNumber = runGenerateNumber 0

runInitGenerator :: Int -> [Word32] -> [Word32]
runInitGenerator i prev =
    case i >= mtSize of
        True -> prev
        False -> runInitGenerator (i+1) $ prev ++ [(fromIntegral i + mtMagic * xor x (shiftR x 30))]
    where x = prev !! (i-1)

runGenerateNumber :: Int -> [Word32] -> [Word32]
runGenerateNumber i mt =
    let y = (mt !! i .&. upperMask) + (mt !! ((i+1) `mod` mtSize) .&. lowerMask)
        (mtL,mtR) = splitAt i mt
        tmpMtI = mt !! ((i + 397) `mod` 624) `xor` shiftR y 1
        tmpMtI' = tmpMtI `xor` matrixA
    in case i >= mtSize of
        True -> mt                   -- when i greater than 623
        False -> if mod y 2 /= 0     -- the rest
                    then runGenerateNumber (i+1) (mtL ++ tmpMtI' : tail mtR)
                    else runGenerateNumber (i+1) (mtL ++ tmpMtI : tail mtR)

extractNumber :: (Int,[Word32]) -> (Int,[Word32],Word32)
extractNumber (mti,mt) =
    let newMt = if mti >= mtSize
            then generateNumber (if mti == mtSize+1
                                    then initGenerator defaultSeed
                                    else mt)
            else mt
        y1 = newMt !! mti
        y2 = y1 `xor` shiftR y1 11
        y3 = y2 `xor` (shiftL y2 7 .&. 0x9d2c5680)
        y4 = y3 `xor` (shiftL y3 15 .&. 0xefc60000)
        y  = y4 `xor` shiftR y4 18
    in (mod (mti + 1) mtSize, newMt, y)



