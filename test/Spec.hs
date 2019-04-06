import Data.Cvss.V3

import Test.HUnit
import Test.Framework
import Test.Framework.Providers.HUnit
import Data.Monoid
import Control.Monad

idTest :: (Read a, Show a, Eq a) => a -> Assertion
idTest v = v @?= (read $ show v)

scoreTest :: (Fractional a, Eq a, Show a) => String -> (a, a, a) -> Assertion
scoreTest v scores = let cvss = read v
                       in (fromRational $ calculateBaseScore cvss, fromRational $ calculateTemporalScore cvss, fromRational $ calculateEnvironmentalScore cvss) @?= scores

main :: IO ()
main = defaultMainWithOpts
       [testCase "id-av:p" $ idTest AttackVectorPhysical
       ,testCase "id-ac:h" $ idTest AttackComplexityHigh
       ,testCase "id-mac:l" $ idTest EnvironmentalAttackComplexityLow
       ,testCase "id-mac:l" $ idTest (read "AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L/E:P/RL:T/RC:C/CR:H/IR:M/AR:H/MAV:N/MAC:L/MPR:N/MUI:R/MS:C/MC:N/MI:H/MA:L" :: CvssV3)
       ,testCase "score1" $ scoreTest "AV:L/AC:L/PR:H/UI:R/S:C/C:L/I:H/A:H" (7.7, 7.7, 7.7)
       ,testCase "score2" $ scoreTest "AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L/E:P/RL:T/RC:C/CR:H/IR:M/AR:H/MAV:N/MAC:L/MPR:N/MUI:R/MS:C/MC:N/MI:H/MA:L" (5.9, 5.4, 7.8)]
       mempty
