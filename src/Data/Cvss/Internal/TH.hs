{-# LANGUAGE TemplateHaskell #-}
module Data.Cvss.Internal.TH (dataDef) where

import Language.Haskell.TH
import Data.List (elemIndex, intercalate, concat, find)
import Data.Maybe (isJust, catMaybes)

--DataD
--  :: Cxt
--     -> Name
--     -> [TyVarBndr]
--     -> Maybe Kind
--     -> [Con]
--     -> [DerivClause]
--     -> Dec

toName = mkName . (filter ((/=)' '))

toLowerInitial [] = []
toLowerInitial orig@(a:rest) = case elemIndex a upper of
                          Just i -> (lower !! i):rest
                          Nothing -> orig
  where
    lower = ['a'..'z']
    upper = ['A'..'Z']

dataDef:: String -> [(String, String, [(String, String)])] -> [(String, [(String, String, [(String, String)])])] -> DecsQ
dataDef topName types optionalTypes = do
  f__dotFunction <- runQ [| (.) |]
  f_catMaybes <- runQ [| catMaybes |]
  f_concat <- runQ [| concat |]
  f_filter <- runQ [| filter |]
  f_find <- runQ [| find |]
  f_flip <- runQ [| flip |]
  f_fst <- runQ [| fst |]
  f_intercalate <- runQ [| intercalate |]
  f_isJust <- runQ [| isJust |]
  f_length <- runQ [| length |]
  f_map <- runQ [| map |]
  f_readParen <- runQ [| readParen |]
  f_snd <- runQ [| snd |]
  f_show <- runQ [| show |]
  ConE n_infix <- runQ [| (:) |]
  createSubTypes' <- flip mapM (("", types):optionalTypes) $ \(category, list) -> flip mapM list $ \(metricName, _, metricValues) ->
                       dataD
                         (return [])
                         (toName $ category ++ metricName)
                         []
                         Nothing
                         (flip map metricValues $ \(name, short) -> normalC (toName $ category ++ metricName ++ name) [])
                         [derivClause Nothing $ map (conT . mkName) ["Eq"]]
  let createSubTypes = concat createSubTypes'
  createTopType <- dataD
                     (return [])
                     (toName topName)
                     []
                     Nothing
                     [recC (toName topName) $ (concat $ flip map (("", types):optionalTypes) $ \(category, types) -> flip map types $ \(metricName, _, _) ->
                                                 varBangType (toName $ toLowerInitial $ category ++ metricName) $
                                                             bangType (return $ Bang NoSourceUnpackedness
                                                                                     NoSourceStrictness) $
                                                                                     conT $ toName $ category ++ metricName)]
                     [derivClause Nothing $ map (conT . mkName) []]
  deriveShowSubs' <- flip mapM (("", types):optionalTypes) $ \(category, types) -> flip mapM types $ \(metricName, metricShort, metricValues) ->
                       instanceD
                         (return [])
                         (appT (conT $ mkName "Show") $ conT $ toName $ category ++ metricName)
                         [funD (mkName "show") $ flip map metricValues $ \(long, short) -> return $ Clause [ConP (toName $ category ++ metricName ++ long) []]
                                                                                                           (NormalB $ LitE $ StringL $ metricShort ++ ":" ++ short)
                                                                                                           []]
  let deriveShowSubs = concat deriveShowSubs'
  deriveShowTop <- do
    varName <- newName "var"
    instanceD
      (return [])
      (appT (conT $ mkName "Show") $ conT $ toName topName)
      [funD (mkName "show") [clause [varP varName]
                                    (normalB $ appE
                                                 (appE (return f_intercalate) $ litE $ stringL "/")
                                                 (appE (return f_concat) $ listE
                                                                    ((listE $ flip map types $ \(metricName, metricShort, _) -> appE (varE $ mkName "show") $ appE (varE $ toName $ toLowerInitial metricName) (varE varName)):
                                                                    (flip map optionalTypes $ \(category, types) -> do
                                                                       valueVar <- newName "value"
                                                                       listVar <- newName "list"
                                                                       letE [valD (varP listVar)
                                                                                  (normalB $ listE $ flip map types $ \(metricName, metricShort, (((defName), _):_)) -> do
                                                                                              matchVar <- newName "match"
                                                                                              caseE (appE (varE $ toName $ toLowerInitial $ category ++ metricName) (varE varName))
                                                                                                       [match (conP (toName $ category ++ metricName ++ defName) []) (normalB $ tupE [conE $ mkName "False", appE (return f_show) $ conE (toName $ category ++ metricName ++ defName)]) []
                                                                                                       ,match (varP matchVar) (normalB $ tupE [conE $ mkName "True", appE (return f_show) $ varE matchVar]) []])
                                                                                  []] $ condE (appE (return f_isJust) 
                                                                                                 (appE (appE (return f_find) (return f_fst)) $
                                                                                                       varE listVar))
                                                                                           (appE (appE (return f_map) (return f_snd)) $ varE listVar)
                                                                                           (listE [])
                                                                    ))))
                                    []]]
  deriveReadSubs' <- flip mapM (("",types):optionalTypes) $ \(category, types) -> flip mapM types $ \(metricName, metricShort, metricValues) -> do
                       depth <- newName "d" 
                       instanceD
                         (return [])
                         (appT (conT $ mkName "Read") $ conT $ toName $ category ++ metricName)
                         [funD (mkName "readsPrec")
                               [clause [varP depth]
                                       (normalB $ appE (appE (return f_readParen) $ conE $ mkName "False") $
                                                        lamCaseE $ flip map metricValues $ \(valueName, valueShort) -> do
                                                                      restVar <- newName "rest" 
                                                                      let str = metricShort ++ ":" ++ valueShort
                                                                      match (return $ foldr (\c rest -> InfixP (LitP $ CharL c) n_infix rest) (VarP restVar) str)
                                                                            (normalB $ listE [tupE [conE $ toName $ category ++ metricName ++ valueName, varE restVar]])
                                                                            [])
                                       []]]
  let deriveReadSubs = concat deriveReadSubs'
  return $ (createTopType:createSubTypes)
        ++ (deriveShowTop:deriveShowSubs)
        ++ (deriveReadSubs)
