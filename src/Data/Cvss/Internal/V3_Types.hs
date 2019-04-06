{-# LANGUAGE TemplateHaskell #-}
module Data.Cvss.Internal.V3_Types where

data Group = Group String String [(String, String)]
           | GroupScored String String [(String, String, Integer)] -- Score in percents

class ScorableCvss a where
  getScore :: a -> Float

groupName (Group name _ _) = name
groupName (GroupScored name _ _) = name

groupShort (Group _ short _) = short
groupShort (GroupScored _ short _) = short

groupSimpleList (Group _ _ list) = list
groupSimpleList (GroupScored _ _ list) = flip map list $ \(s1, s2, _) -> (s1, s2)

groupToSimple group = (groupName group, groupShort group, groupSimpleList group)

baseVectors = [(GroupScored "Attack Vector" "AV" [("Network", "N", 85), ("Adjacent Network", "A", 62),
                                                  ("Local", "L", 55), ("Physical", "P", 20)]),
               (GroupScored "Attack Complexity" "AC" [("Low", "L", 77), ("High", "H", 44)]),
               (Group "Privileges Required" "PR" [("None", "N"), ("Low", "L"), ("High", "H")]),
               (GroupScored "User Interaction" "UI" [("None", "N", 85), ("Required", "R", 62)]),
               (Group "Scope" "S" [("Unchanged", "U"), ("Changed", "C")]),
               (GroupScored "Confidentiality Impact" "C" [("None", "N", 0), ("Low", "L", 22), ("High", "H", 56)]),
               (GroupScored "Integrity Impact" "I" [("None", "N", 0), ("Low", "L", 22), ("High", "H", 56)]),
               (GroupScored "Availability Impact" "A" [("None", "N", 0), ("Low", "L", 22), ("High", "H", 56)])]

baseToEnvironmental [] = []
baseToEnvironmental ((Group name short list):rest) = (Group name ("M" ++ short) (("Not Defined", "X"):list)):baseToEnvironmental rest
baseToEnvironmental ((GroupScored name short list):rest) = (GroupScored name ("M" ++ short) (("Not Defined", "X", 100):list)):baseToEnvironmental rest

allVectors = (baseVectors,
             [("Temporal", [(GroupScored "Exploitability" "E" [("Not Defined", "X", 100)
                                                              ,("Unproven That Exploit Exists", "U", 91)
                                                              ,("Proof Of Concept Code", "P", 94)
                                                              ,("Functional Exploit Exists", "F", 97)
                                                              ,("High", "H", 100)]),
                            (GroupScored "Remediation Level" "RL" [("Not Defined", "X", 100)
                                                                  ,("Official Fix", "O", 95)
                                                                  ,("Temporary Fix", "T", 96)
                                                                  ,("Workaround", "W", 97)
                                                                  ,("Unavailable", "U", 100)]),
                            (GroupScored "Report Confidence" "RC" [("Not Defined", "X", 100)
                                                                  ,("Unknown", "U", 92)
                                                                  ,("Reasonable", "R", 96)
                                                                  ,("Confirmed", "C", 100)])])
             ,("Environmental", [(GroupScored "Confidentiality Requirement" "CR" [("Not Defined", "X", 100), ("Low", "L", 50), ("Medium", "M", 100), ("High", "H", 150)])
                                ,(GroupScored "Integrity Requirement" "IR" [("Not Defined", "X", 100), ("Low", "L", 50), ("Medium", "M", 100), ("High", "H", 150)])
                                ,(GroupScored "Availability Requirement" "AR" [("Not Defined", "X", 100), ("Low", "L", 50), ("Medium", "M", 100), ("High", "H", 150)])] ++
                                (baseToEnvironmental baseVectors))])
