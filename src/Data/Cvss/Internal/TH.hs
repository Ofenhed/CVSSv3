{-# LANGUAGE TemplateHaskell #-}
module Data.Cvss.Internal.TH (dataDef) where

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
  ConE n_infix <- runQ [| (:) |]
  createSubTypes' <- flip mapM ((Nothing, types):(map (\(v1, v2) -> (Just v1, v2)) optionalTypes)) $ \(category, list) -> flip mapM list $ \(metricName, _, metricValues) -> let category' = case category of Just c -> c ; _ -> "" in
                       dataD
                         (return [])
                         (toName $ category' ++ metricName)
                         []
                         Nothing
                         (flip map metricValues $ \(name, short) -> normalC (toName $ category' ++ metricName ++ name) [])
                         [derivClause Nothing $ map (conT . mkName) ["Eq"]]
  let createSubTypes = concat createSubTypes'
  createTopType <- dataD
                     (return [])
                     (toName topName)
                     []
                     Nothing
                     [recC (toName topName) $ (flip map types $ \(metricName, _, _) -> varBangType (toName $ toLowerInitial metricName) $ bangType (return $ Bang NoSourceUnpackedness NoSourceStrictness) $ conT $ toName metricName)
                                           ++ (flip map optionalTypes $ \(categoryName, types) -> varBangType (toName $ toLowerInitial categoryName) $ bangType (return $ Bang NoSourceUnpackedness NoSourceStrictness) $ appT (conT $ mkName "Maybe") $ 
                                                    (foldr (\(metricName, _, _) rest -> appT rest $ conT $ toName $ categoryName ++ metricName) (tupleT $ length types) types))]
                     [derivClause Nothing $ map (conT . mkName) []]
  deriveShowSubs <- flip mapM types $ \(metricName, metricShort, metricValues) ->
                      instanceD
                        (return [])
                        (appT (conT $ mkName "Show") $ conT $ toName metricName)
                        [funD (mkName "show") $ flip map metricValues $ \(long, short) -> return $ Clause [ConP (toName $ metricName ++ long) []]
                                                                                                          (NormalB $ LitE $ StringL $ metricShort ++ ":" ++ short)
                                                                                                          []]
  deriveShowTop <- do
    varName <- newName "var"
    instanceD
      (return [])
      (appT (conT $ mkName "Show") $ conT $ toName topName)
      [funD (mkName "show") [return $ Clause [VarP varName]
                                             (NormalB $ AppE
                                                          (AppE f_intercalate $ LitE $ StringL "/") $
                                                          ListE $ flip map types $ \(metricName, metricShort, _) -> AppE (VarE $ mkName "show") $ AppE (VarE $ toName $ toLowerInitial metricName) (VarE varName))
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
