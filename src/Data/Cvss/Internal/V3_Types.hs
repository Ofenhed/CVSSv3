{-# LANGUAGE TemplateHaskell #-}
module Data.Cvss.Internal.V3_Types where
import Data.Cvss.Internal.V3_Generator

-- data BaseProperties = AttackVector AttackVector
--                     | AttackComplexity AttackComplexity
--                     | PrivilegesRequired PrivilegesRequired deriving (Show, Read)

$(generator)

--testPrec :: Int -> String -> [(CvssV3, String)]
--testPrec d r = 
--                flip concatMap (map (\x -> (CvssV3, x)) $ readsPrec (d+1) r) $ \(builder, (var, '/':rest)) ->
--                  concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
--                    concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
--                      concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
--                      concat $ [[(builder var TemporalReportConfidenceNotDefined EnvironmentalAttackVectorNotDefined EnvironmentalAttackComplexityNotDefined, rest)],
--                                flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
--                      concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
--                        concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, rest)) -> [(builder var, rest)]]]]]]]

