import Data.Cvss.V3

import Test.HUnit
import Test.Framework
import Test.Framework.Providers.HUnit
import Data.Monoid
import Control.Monad

idTest :: (Read a, Show a, Eq a) => a -> Assertion
idTest v = v @?= (read $ show v)

main :: IO ()
main = defaultMainWithOpts
       [testCase "id-av:p" $ idTest AttackVectorPhysical
       ,testCase "id-ac:h" $ idTest AttackComplexityHigh]
       mempty
