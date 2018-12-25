module Data.Cvss.Internal.V3
    () where

import Data.Maybe (fromJust)
import Data.Tuple (swap)
import Data.Cvss.Internal.V3_Types

-- instance Show AttackVector where
--  show d = "AV:" ++ [fromJust $ lookup d avTable]
--instance Read AttackVector where
--  readsPrec d = readParen False $ \r -> do
--                  case r of
--                    ('A':'V':':':c:rest) -> return (fromJust $ lookup c (map swap avTable), rest)
--avTable = [(AttackVectorNetwork, 'N')
--          ,(AttackVectorAdjacentNetwork, 'A')
--          ,(AttackVectorLocal, 'L')
--          ,(AttackVectorPhysical, 'P')]
--
--instance Show AttackComplexity where
--  show d = "AC:" ++ [fromJust $ lookup d acTable]
--instance Read AttackComplexity where
--  readsPrec d = readParen False $ \r -> do
--                  case r of
--                    ('A':'C':':':c:rest) -> return (fromJust $ lookup c (map swap acTable), rest)
--acTable = [(AttackComplexityLow, 'L')
--          ,(AttackComplexityHigh, 'H')]
--
--instance Show PrivilegesRequired where
--  show d = "PR:" ++ [fromJust $ lookup d prTable]
--instance Read PrivilegesRequired where
--  readsPrec d = readParen False $ \r -> do
--                  case r of
--                    ('P':'R':':':c:rest) -> return (fromJust $ lookup c (map swap prTable), rest)
--prTable = [(PrivilegesRequiredNone, 'N')
--          ,(PrivilegesRequiredLow, 'L')
--          ,(PrivilegesRequiredHigh, 'H')]
