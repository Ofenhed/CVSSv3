{-# LANGUAGE TemplateHaskell #-}
module Data.Cvss.Internal.V3_Generator where
import Data.Cvss.Internal.V3_Types (ScorableCvss(..))
import qualified Data.Cvss.Internal.V3_Types as Internal
import qualified Data.Cvss.Internal.TH as Internal

$(Internal.dataDef "CvssV3" (fst Internal.allVectors) (snd Internal.allVectors))
