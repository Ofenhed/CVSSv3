module Data.Cvss.Internal.TH where

import Language.Haskell.TH
import Data.List (elemIndex)

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
  d1 <- flip mapM types $ \(metricName, _, _, metricValues) ->
          dataD
            (return [])
            (mkName metricName)
            []
            Nothing
            (flip map metricValues $ \(name, short) -> normalC (mkName $ metricName ++ name) [])
            [derivClause Nothing $ map (conT . mkName) ["Eq"]]
  d2 <- dataD
          (return [])
          (mkName topName)
          []
          Nothing
          [recC (mkName topName) $ flip map types $ \(metricName, metricShort, metricRequired, _) -> varBangType (mkName $ toLowerInitial metricName) $ bangType (return $ Bang NoSourceUnpackedness NoSourceStrictness) $ conT $ mkName metricName]
          [derivClause Nothing $ map (conT . mkName) ["Show"]]
  d3 <- flip mapM types $ \(metricName, metricShort, _, metricValues) ->
          instanceD
            (return [])
            (appT (conT $ mkName "Show") $ conT $ mkName metricName)
            -- [funD (mkName "show") [return $ Clause [VarP $ mkName "a"]
            --                                 (NormalB $ LitE $ StringL $ metricShort)
            --                                 []]]
            [funD (mkName "show") $ flip map metricValues $ \(long, short) -> return $ Clause [ConP (mkName $ metricName ++ long) []]
                                                                                              (NormalB $ LitE $ StringL $ metricShort ++ ":" ++ short)
                                                                                              []]
  return $ (d2:d1) ++ d3
