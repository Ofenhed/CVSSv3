{-# LANGUAGE TemplateHaskell #-}
module Data.Cvss.Internal.V3_Types where
import Data.Cvss.Internal.TH

-- data BaseProperties = AttackVector AttackVector
--                     | AttackComplexity AttackComplexity
--                     | PrivilegesRequired PrivilegesRequired deriving (Show, Read)

$(dataDef "CvssV3" [("AttackVector", "AV", True, [("Network", "N"), ("AdjacentNetwork", "A"),
                                                  ("Local", "L"), ("Physical", "P")]),
                    ("AttackComplexity", "AC", True, [("Low", "L"), ("High", "H")]),
                    ("PrivilegesRequired", "PR", True, [("None", "N"), ("Low", "L"), ("High", "H")])])
