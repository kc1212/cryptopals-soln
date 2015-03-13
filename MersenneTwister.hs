
module MersenneTwister (
    initGenerator,
    extractNumber,
    generateNumber,
    wordFromSeed,
    listFromSeed)
where

import Data.Word (Word32)
import Data.Bits

-- MT19937 parameters
mtSize = 624
mtMagic = 0x6c078965
upperMask = 0x80000000
lowerMask = 0x7fffffff
matrixA = 0x9908b0df
defaultSeed = 5489

initGenerator :: Word32 -> (Int,[Word32])
initGenerator seed = (0,runInitGenerator 1 [seed])

generateNumber :: [Word32] -> [Word32]
generateNumber = runGenerateNumber 0

runInitGenerator :: Int -> [Word32] -> [Word32]
runInitGenerator i prev =
    case i >= mtSize of
        True -> prev
        False -> runInitGenerator (i+1) $
                    prev ++ [(fromIntegral i + mtMagic * xor x (shiftR x 30))]
    where x = prev !! (i-1)

runGenerateNumber :: Int -> [Word32] -> [Word32]
runGenerateNumber i mt =
    let y = (mt !! i .&. upperMask) + (mt !! ((i+1) `mod` mtSize) .&. lowerMask)
        (mtL,mtR) = splitAt i mt
        tmpMtI = mt !! ((i + 397) `mod` 624) `xor` shiftR y 1
        tmpMtI' = tmpMtI `xor` matrixA
    in case i >= mtSize of
        True -> mt
        False -> if mod y 2 /= 0
                    then runGenerateNumber (i+1) (mtL ++ tmpMtI' : tail mtR)
                    else runGenerateNumber (i+1) (mtL ++ tmpMtI : tail mtR)

extractNumber :: (Int, [Word32]) -> ((Int,[Word32]),Word32)
extractNumber (index,mt) =
    let imt = if index == 0 then generateNumber mt else mt
        y1 = imt !! index
        y2 = y1 `xor` shiftR y1 11
        y3 = y2 `xor` (shiftL y2 7 .&. 0x9d2c5680)
        y4 = y3 `xor` (shiftL y3 15 .&. 0xefc60000)
        y  = y4 `xor` shiftR y4 18
    in ((mod (index + 1) mtSize, imt), y)

wordFromSeed :: Word32 -> Word32
wordFromSeed = snd . extractNumber . initGenerator

listFromSeed :: Word32 -> Int -> [Word32]
listFromSeed seed n = runListFromSeed n (initGenerator seed)

runListFromSeed :: Int -> (Int,[Word32]) -> [Word32]
runListFromSeed 0 _ = undefined
runListFromSeed 1 state  = [snd . extractNumber $ state]
runListFromSeed n state =
    let (nextState, res) = extractNumber state
    in res : runListFromSeed (n-1) nextState


