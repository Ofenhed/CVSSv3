{-# LANGUAGE TemplateHaskell #-}
module Data.Cvss.Internal.TH where

import Language.Haskell.TH
import Data.List (elemIndex, intercalate)

--DataD
--  :: Cxt
--     -> Name
--     -> [TyVarBndr]
--     -> Maybe Kind
--     -> [Con]
--     -> [DerivClause]
--     -> Dec

toLowerInitial [] = []
toLowerInitial orig@(a:rest) = case elemIndex a upper of
                          Just i -> (lower !! i):rest
                          Nothing -> orig
  where
    lower = ['a'..'z']
    upper = ['A'..'Z']

dataDef:: String -> [(String, String, Bool, [(String, String)])] -> DecsQ
dataDef topName types = do
  f_intercalate <- runQ [| intercalate |]
  f_readParen <- runQ [| readParen |]
  ConE n_infix <- runQ [| (:) |]
  createSubTypes <- flip mapM types $ \(metricName, _, _, metricValues) ->
                      dataD
                        (return [])
                        (mkName metricName)
                        []
                        Nothing
                        (flip map metricValues $ \(name, short) -> normalC (mkName $ metricName ++ name) [])
                        [derivClause Nothing $ map (conT . mkName) ["Eq"]]
  createTopType <- dataD
                     (return [])
                     (mkName topName)
                     []
                     Nothing
                     [recC (mkName topName) $ flip map types $ \(metricName, metricShort, metricRequired, _) -> varBangType (mkName $ toLowerInitial metricName) $ bangType (return $ Bang NoSourceUnpackedness NoSourceStrictness) $ conT $ mkName metricName]
                     [derivClause Nothing $ map (conT . mkName) []]
  deriveShowSubs <- flip mapM types $ \(metricName, metricShort, _, metricValues) ->
                      instanceD
                        (return [])
                        (appT (conT $ mkName "Show") $ conT $ mkName metricName)
                        [funD (mkName "show") $ flip map metricValues $ \(long, short) -> return $ Clause [ConP (mkName $ metricName ++ long) []]
                                                                                                          (NormalB $ LitE $ StringL $ metricShort ++ ":" ++ short)
                                                                                                          []]
  deriveShowTop <- do
    varName <- newName "var"
    instanceD
      (return [])
      (appT (conT $ mkName "Show") $ conT $ mkName topName)
      [funD (mkName "show") [return $ Clause [VarP varName]
                                             (NormalB $ AppE
                                                          (AppE f_intercalate $ LitE $ StringL "/") $
                                                          ListE $ flip map types $ \(metricName, metricShort, _, _) -> AppE (VarE $ mkName "show") $ AppE (VarE $ mkName $ toLowerInitial metricName) (VarE varName))
                                             []]]
  deriveReadSubs <- flip mapM types $ \(metricName, metricShort, _, metricValues) -> do
                      depth <- newName "d" 
                      instanceD
                        (return [])
                        (appT (conT $ mkName "Read") $ conT $ mkName metricName)
                        [funD (mkName "readsPrec")
                              [clause [varP depth]
                                      (normalB $ appE (appE (return f_readParen) $ conE $ mkName "False") $
                                                       lamCaseE $ flip map metricValues $ \(valueName, valueShort) -> do
                                                                     restVar <- newName "rest" 
                                                                     let str = metricShort ++ ":" ++ valueShort
                                                                     match (return $ foldr (\c rest -> InfixP (LitP $ CharL c) n_infix rest) (VarP restVar) str)
                                                                           (normalB $ listE [tupE [conE $ mkName $ metricName ++ valueName, varE restVar]])
                                                                           [])
                                      []]]
  return $ (createTopType:createSubTypes)
        ++ (deriveShowTop:deriveShowSubs)
        ++ (deriveReadSubs)
