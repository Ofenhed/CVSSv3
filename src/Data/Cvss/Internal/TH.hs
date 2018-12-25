{-# LANGUAGE TemplateHaskell #-}
module Data.Cvss.Internal.TH (dataDef) where

import Language.Haskell.TH
import Data.List (elemIndex, intercalate, concat)

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
  f_intercalate <- runQ [| intercalate |]
  f_readParen <- runQ [| readParen |]
  f_concat <- runQ [| concat |]
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
    match <- newName "patternMatch"
    instanceD
      (return [])
      (appT (conT $ mkName "Show") $ conT $ toName topName)
      [funD (mkName "show") [return $ Clause [VarP varName]
                                             (NormalB $ AppE
                                                          (AppE f_intercalate $ LitE $ StringL "/")
                                                          (AppE f_concat $ ListE
                                                                             ((ListE $ flip map types $ \(metricName, metricShort, _) -> AppE (VarE $ mkName "show") $ AppE (VarE $ toName $ toLowerInitial metricName) (VarE varName)):
                                                                             (flip map optionalTypes $ \(category, types) ->
                                                                                ListE $ flip map types $ \(metricName, metricShort, (((defName), _):_)) -> AppE (VarE $ mkName "show") $
                                                                                  CaseE (AppE (VarE $ toName $ toLowerInitial $ category ++ metricName) (VarE varName))
                                                                                           [Match (ConP (toName $ category ++ metricName ++ defName) []) (NormalB $ TupE [ConE $ mkName "False", ConE (toName $ category ++ metricName ++ defName)]) []
                                                                                           ,Match (VarP match) (NormalB $ TupE [ConE $ mkName "True", VarE match]) []]
                                                                             ))))
                                             []]]
  deriveReadSubs <- flip mapM types $ \(metricName, metricShort, metricValues) -> do
                      depth <- newName "d" 
                      instanceD
                        (return [])
                        (appT (conT $ mkName "Read") $ conT $ toName metricName)
                        [funD (mkName "readsPrec")
                              [clause [varP depth]
                                      (normalB $ appE (appE (return f_readParen) $ conE $ mkName "False") $
                                                       lamCaseE $ flip map metricValues $ \(valueName, valueShort) -> do
                                                                     restVar <- newName "rest" 
                                                                     let str = metricShort ++ ":" ++ valueShort
                                                                     match (return $ foldr (\c rest -> InfixP (LitP $ CharL c) n_infix rest) (VarP restVar) str)
                                                                           (normalB $ listE [tupE [conE $ toName $ metricName ++ valueName, varE restVar]])
                                                                           [])
                                      []]]
  return $ (createTopType:createSubTypes)
        ++ (deriveShowTop:deriveShowSubs)
        ++ (deriveReadSubs)
