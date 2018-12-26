{-# LANGUAGE TemplateHaskell #-}
module Data.Cvss.Internal.V3_Types where

baseVectors = [("Attack Vector", "AV", [("Network", "N"), ("Adjacent Network", "A"),
                                            ("Local", "L"), ("Physical", "P")]),
                    ("Attack Complexity", "AC", [("Low", "L"), ("High", "H")]),
                    ("Privileges Required", "PR", [("None", "N"), ("Low", "L"), ("High", "H")]),
                    ("User Interaction", "UI", [("None", "N"), ("Required", "R")]),
                    ("Scope", "S", [("Unchanged", "U"), ("Changed", "C")]),
                    ("Confidentiality Impact", "C", [("None", "N"), ("Low", "L"), ("High", "H")]),
                    ("Integrity Impact", "I", [("None", "N"), ("Low", "L"), ("High", "H")]),
                    ("Availability Impact", "A", [("None", "N"), ("Low", "L"), ("High", "H")])]

baseToEnvironmental [] = []
baseToEnvironmental ((name, short, list):rest) = (name, "M" ++ short, ("Not Defined", "X"):list):baseToEnvironmental rest

allVectors = (baseVectors,
             [("Temporal", [("Exploitability", "E", [("Not Defined", "X")
                                                    ,("Unproven That Exploit Exists", "U")
                                                    ,("Proof Of Concept Code", "P")
                                                    ,("Functional Exploit Exists", "F")
                                                    ,("High", "H")]),
                            ("Remediation Level", "RL", [("Not Defined", "X")
                                                        ,("Official Fix", "O")
                                                        ,("Temporary Fix", "T")
                                                        ,("Workaround", "W")
                                                        ,("Unavailable", "U")]),
                            ("Report Confidence", "RC", [("Not Defined", "X")
                                                        ,("Unknown", "U")
                                                        ,("Reasonable", "R")
                                                        ,("Confirmed", "C")])])
             ,("Environmental", [("Confidentiality Requirement", "CR", [("Not Defined", "X"), ("Low", "L"), ("Medium", "M"), ("High", "H")])
                                ,("Integrity Requirement", "IR", [("Not Defined", "X"), ("Low", "L"), ("Medium", "M"), ("High", "H")])
                                ,("Availability Requirement", "AR", [("Not Defined", "X"), ("Low", "L"), ("Medium", "M"), ("High", "H")])] ++
                                (baseToEnvironmental baseVectors))])
