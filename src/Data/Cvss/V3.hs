{-# LANGUAGE MultiParamTypeClasses #-}
module Data.Cvss.V3 (module Data.Cvss.Internal.V3, calculateBaseScore, calculateTemporalScore, calculateEnvironmentalScore) where

import Data.Cvss.Internal.V3
import Data.Ratio ((%), numerator, denominator)

roundOne x = (ceiling $ 10 * x) % 10

calculateBaseScore :: CvssV3 -> Rational
calculateBaseScore metric = if impactSubScore <= 0
                              then 0
                              else case scope metric of
                                     ScopeUnchanged -> roundOne $ min (impactSubScore + exploitability) 10
                                     ScopeChanged -> roundOne $ min (1.08 * (impactSubScore + exploitability)) 10
  where
  impactSubScore = case scope metric of
                     ScopeUnchanged -> 6.42 * iscBase
                     ScopeChanged -> 7.52 * (iscBase-0.029) - 3.25 * ((iscBase - 0.02) ^ 15)
  iscBase = 1 - ((1 - (getScore $ confidentialityImpact metric)) * (1 - (getScore $ integrityImpact metric)) * (1 - (getScore $ availabilityImpact metric)))
  privilegesRequiredScore = case privilegesRequired metric of
                              PrivilegesRequiredNone -> 0.85
                              PrivilegesRequiredLow -> case scope metric of
                                                         ScopeUnchanged -> 0.62
                                                         ScopeChanged -> 0.68
                              PrivilegesRequiredHigh -> case scope metric of
                                                          ScopeUnchanged -> 0.27
                                                          ScopeChanged -> 0.50
  exploitability = 8.22 * (getScore $ attackVector metric) * (getScore $ attackComplexity metric) * privilegesRequiredScore * (getScore $ userInteraction metric)
                            
calculateTemporalScore :: CvssV3 -> Rational
calculateTemporalScore metric = roundOne $ (fromRational $ calculateBaseScore metric) * (getScore $ temporalExploitability metric) * (getScore $ temporalRemediationLevel metric) * (getScore $ temporalReportConfidence metric)

class SuperType a b where
  typeOr :: a -> b -> b
instance SuperType EnvironmentalScope Scope where
  typeOr EnvironmentalScopeNotDefined s = s
  typeOr EnvironmentalScopeChanged _ = ScopeChanged
  typeOr EnvironmentalScopeUnchanged _ = ScopeUnchanged
instance SuperType EnvironmentalPrivilegesRequired PrivilegesRequired where
  typeOr EnvironmentalPrivilegesRequiredNotDefined s = s
  typeOr EnvironmentalPrivilegesRequiredNone _ = PrivilegesRequiredNone
  typeOr EnvironmentalPrivilegesRequiredLow _ = PrivilegesRequiredLow
  typeOr EnvironmentalPrivilegesRequiredHigh _ = PrivilegesRequiredHigh

class (ScorableCvss a, ScorableCvss b) => ScoredSuperType a b where
  scoreOr :: a -> b -> Float
instance ScoredSuperType EnvironmentalConfidentialityImpact ConfidentialityImpact where
  scoreOr EnvironmentalConfidentialityImpactNotDefined x = getScore x
  scoreOr x _ = getScore x
instance ScoredSuperType EnvironmentalIntegrityImpact IntegrityImpact where
  scoreOr EnvironmentalIntegrityImpactNotDefined x = getScore x
  scoreOr x _ = getScore x
instance ScoredSuperType EnvironmentalAvailabilityImpact AvailabilityImpact where
  scoreOr EnvironmentalAvailabilityImpactNotDefined x = getScore x
  scoreOr x _ = getScore x
instance ScoredSuperType EnvironmentalAttackVector AttackVector where
  scoreOr EnvironmentalAttackVectorNotDefined x = getScore x
  scoreOr x _ = getScore x
instance ScoredSuperType EnvironmentalAttackComplexity AttackComplexity where
  scoreOr EnvironmentalAttackComplexityNotDefined x = getScore x
  scoreOr x _ = getScore x
instance ScoredSuperType EnvironmentalUserInteraction UserInteraction where
  scoreOr EnvironmentalUserInteractionNotDefined x = getScore x
  scoreOr x _ = getScore x

calculateEnvironmentalScore :: CvssV3 -> Rational
calculateEnvironmentalScore metric = if modImpactSubScore <= 0
                                       then 0
                                       else case typeOr (environmentalScope metric) $ scope metric of
                                              ScopeChanged -> roundOne $ (fromRational $ roundOne $ min (1.08 * (modImpactSubScore + modExploitability)) 10) * (getScore $ temporalExploitability metric) * (getScore $ temporalRemediationLevel metric) * (getScore $ temporalReportConfidence metric)
                                              ScopeUnchanged -> roundOne $ (fromRational $ roundOne $ min (modImpactSubScore + modExploitability) 10) * (getScore $ temporalExploitability metric) * (getScore $ temporalRemediationLevel metric) * (getScore $ temporalReportConfidence metric)
  where
  modPrivilegesRequiredScore = case typeOr (environmentalPrivilegesRequired metric) $ privilegesRequired metric of
                                 PrivilegesRequiredNone -> 0.85
                                 PrivilegesRequiredLow -> case typeOr (environmentalScope metric) $ scope metric of
                                                               ScopeUnchanged -> 0.62
                                                               ScopeChanged -> 0.68
                                 PrivilegesRequiredHigh -> case typeOr (environmentalScope metric) $ scope metric of
                                                                ScopeUnchanged -> 0.27
                                                                ScopeChanged -> 0.50
  modImpactSubScore = case typeOr (environmentalScope metric) $ scope metric of
                        ScopeChanged -> 7.52 * (iscMod - 0.029) - 3.25 * ((iscMod - 0.02)^15)
                        ScopeUnchanged -> 6.42 * iscMod
  iscMod = min 0.915 (1 - (1 - (scoreOr (environmentalConfidentialityImpact metric) $ confidentialityImpact metric) * (getScore $ environmentalConfidentialityRequirement metric)) * 
                          (1 - (scoreOr (environmentalIntegrityImpact metric) $ integrityImpact metric) * (getScore $ environmentalIntegrityRequirement metric)) *
                          (1 - (scoreOr (environmentalAvailabilityImpact metric) $ availabilityImpact metric) * (getScore $ environmentalAvailabilityRequirement metric)))
  modExploitability = 8.22 * (scoreOr (environmentalAttackVector metric) $ attackVector metric) *
                             (scoreOr (environmentalAttackComplexity metric) $ attackComplexity metric) * 
                             modPrivilegesRequiredScore * 
                             (scoreOr (environmentalUserInteraction metric) $ userInteraction metric)
