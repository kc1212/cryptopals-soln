
module MersenneTwister (
    initGenerator,
    extractNumber,
    generateNumber,
    wordFromSeed,
    listFromSeed,
    temper,
    untemper
) where

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
        y = temper (imt !! index)
    in ((mod (index + 1) mtSize, imt), y)

temper :: Word32 -> Word32
temper inp =
    let y2 = inp `xor` shiftR inp 11
        y3 = y2 `xor` (shiftL y2 7 .&. 0x9d2c5680)
        y4 = y3 `xor` (shiftL y3 15 .&. 0xefc60000)
        y  = y4 `xor` shiftR y4 18
    in y

untemper :: Word32 -> Word32
untemper inp =
    let
        y1  = inp `xor` (shiftR inp 18)

        y2a = y1 `xor` 0xefc60000                      -- bit 0..14
        y2b = y1 `xor` (shiftL y2a 15 .&. 0xefc60000)  -- bit 15..29
        y2c = y1 `xor` (shiftL y2b 15 .&. 0xefc60000)  -- bit 30..31
        y2  = y2c .&. 0xC0000000 `xor` y2b .&. 0x3FFF8000 `xor` y2a .&. 0x00007FFF

        y3a = y2  `xor` 0x9d2c5680                     -- bit 0..6
        y3b = y2 `xor` (shiftL y3a 7 .&. 0x9d2c5680)   -- bit 7..13
        y3c = y2 `xor` (shiftL y3b 7 .&. 0x9d2c5680)   -- bit 14..20
        y3d = y2 `xor` (shiftL y3c 7 .&. 0x9d2c5680)   -- bit 21..27
        y3e = y2 `xor` (shiftL y3d 7 .&. 0x9d2c5680)   -- bit 28..31
        y3  = y3e .&. 0xF0000000 `xor` y3d .&. 0x0FE00000 `xor` y3c .&. 0x001FC000 `xor`
              y3b .&. 0x00003F80 `xor` y3a .&. 0x0000007F

        y4a = y3                                       -- bit 21..31
        y4b = y3 `xor` (shiftR y4a 11)                 -- bit 10..20
        y4c = y3 `xor` (shiftR y4b 11)                 -- bit 0..9
        y4  = y4a .&. 0xFFE00000 `xor` y4b .&. 0x001FFC00 `xor` y4c .&. 0x000003FF

    in y4

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


