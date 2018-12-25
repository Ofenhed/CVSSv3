{-# LANGUAGE TemplateHaskell #-}
module Data.Cvss.Internal.V3_Types where
import Data.Cvss.Internal.TH

-- data BaseProperties = AttackVector AttackVector
--                     | AttackComplexity AttackComplexity
--                     | PrivilegesRequired PrivilegesRequired deriving (Show, Read)

import Debug.Trace

$(dataDef "CvssV3" [("AttackVector", "AV", [("Network", "N"), ("Adjacent Network", "A"),
                                            ("Local", "L"), ("Physical", "P")]),
                    ("AttackComplexity", "AC", [("Low", "L"), ("High", "H")]),
                    ("PrivilegesRequired", "PR", [("None", "N"), ("Low", "L"), ("High", "H")])]
                   [("Temporal", [("Exploitability", "E", [("Not Defined", "X")
                                                          ,("Unproven That Exploit Exists", "U")]),
                                  ("ReportConfidence", "RC", [("Not Defined", "X")
                                                          ,("Unknown", "U")])])
                   ,("Environmental", [("Attack Vector", "MAV", [("Not Defined", "X")
                                                                ,("Network", "N")])
                                      ,("Attack Complexity", "MAC", [("Not Defined", "X")
                                                                    ,("Low", "L")])])])


testPrec :: Int -> String -> [(CvssV3, String)]
testPrec d r = 
                flip concatMap (map (\x -> (CvssV3, x)) $ readsPrec (d+1) r) $ \(builder, (var, '/':rest)) ->
                  concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
                    concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
                      concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
                      concat $ [[(builder var TemporalReportConfidenceNotDefined EnvironmentalAttackVectorNotDefined EnvironmentalAttackComplexityNotDefined, rest)],
                                flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
                      concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
                        concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, rest)) -> [(builder var, rest)]]]]]]]

