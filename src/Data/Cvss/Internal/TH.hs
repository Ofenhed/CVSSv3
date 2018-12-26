{-# LANGUAGE TemplateHaskell #-}
module Data.Cvss.Internal.TH (dataDef) where

import Language.Haskell.TH
import Data.List (elemIndex, intercalate, concat, find, concatMap)
import Data.Maybe (isJust, catMaybes)

toName = mkName . (filter ((/=)' '))

toLowerInitial [] = []
toLowerInitial orig@(a:rest) = case elemIndex a upper of
                          Just i -> (lower !! i):rest
                          Nothing -> orig
  where
    lower = ['a'..'z']
    upper = ['A'..'Z']

type SubTypeEnum = (String, String)
type SubTypeEnums = [SubTypeEnum]
type SubTypeSpecification = (String, String, SubTypeEnums)
type OptionalSubTypeSpecification = (String, SubTypeSpecification)


dataDef:: String -> [(String, String, [(String, String)])] -> [(String, [(String, String, [(String, String)])])] -> DecsQ
dataDef topName types optionalTypes = do
  let f__dotFunction = [| (.) |]
  let f_catMaybes = [| catMaybes |]
  let f_concat = [| concat |]
  let f_concatMap = [| concatMap |]
  let f_filter = [| filter |]
  let f_find = [| find |]
  let f_flip = [| flip |]
  let f_fst = [| fst |]
  let f_intercalate = [| intercalate |]
  let f_isJust = [| isJust |]
  let f_length = [| length |]
  let f_map = [| map |]
  let f_readParen = [| readParen |]
  let f_readsPrec = [| readsPrec |]
  let f_snd = [| snd |]
  let f_show = [| show |]
  ConE n_infix <- [| (:) |]
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
                                                 (appE (f_intercalate) $ litE $ stringL "/")
                                                 (appE (f_concat) $ listE
                                                                    ((listE $ flip map types $ \(metricName, metricShort, _) -> appE (varE $ mkName "show") $ appE (varE $ toName $ toLowerInitial metricName) (varE varName)):
                                                                    (flip map optionalTypes $ \(category, types) -> do
                                                                       valueVar <- newName "value"
                                                                       listVar <- newName "list"
                                                                       letE [valD (varP listVar)
                                                                                  (normalB $ listE $ flip map types $ \(metricName, metricShort, (((defName), _):_)) -> do
                                                                                              matchVar <- newName "match"
                                                                                              caseE (appE (varE $ toName $ toLowerInitial $ category ++ metricName) (varE varName))
                                                                                                       [match (conP (toName $ category ++ metricName ++ defName) []) (normalB $ tupE [conE $ mkName "False", appE (f_show) $ conE (toName $ category ++ metricName ++ defName)]) []
                                                                                                       ,match (varP matchVar) (normalB $ tupE [conE $ mkName "True", appE (f_show) $ varE matchVar]) []])
                                                                                  []] $ condE (appE (f_isJust) 
                                                                                                 (appE (appE (f_find) (f_fst)) $
                                                                                                       varE listVar))
                                                                                           (appE (appE (f_map) (f_snd)) $ varE listVar)
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
                                       (normalB $ appE (appE (f_readParen) $ conE $ mkName "False") $
                                                        lamCaseE $ (flip map metricValues $ \(valueName, valueShort) -> do
                                                                      restVar <- newName "rest" 
                                                                      let str = metricShort ++ ":" ++ valueShort
                                                                      match (return $ foldr (\c rest -> InfixP (LitP $ CharL c) n_infix rest) (VarP restVar) str)
                                                                            (normalB $ listE [tupE [conE $ toName $ category ++ metricName ++ valueName, varE restVar]])
                                                                            []
                                                                   ) ++ [match wildP
                                                                               (normalB $ listE [])
                                                                               []]
                                       )
                                       []]]
  let deriveReadSubs = concat deriveReadSubs'
-- testPrec :: Int -> String -> [(CvssV3, String)]
-- testPrec d r = 
--                 flip concatMap (map (\x -> (CvssV3, x)) $ readsPrec (d+1) r) $ \(builder, (var, '/':rest)) ->
--                   concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
--                     concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
--                       concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
--                       concat $ [[(builder var TemporalReportConfidenceNotDefined EnvironmentalAttackVectorNotDefined EnvironmentalAttackComplexityNotDefined, rest)],
--                                 flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
--                       concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, '/':rest)) ->
--                         concat $ [flip concatMap (map (\x -> (builder var, x)) $ readsPrec (d+1) $ traceShowId rest) $ \(builder, (var, rest)) -> [(builder var, rest)]]]]]]]

  deriveReadTop <- do
    recursiveRead <- newName "read"
    depth <- newName "d"
    builder <- newName "builder"
    var <- newName "var"
    x <- newName "x"
    rest <- newName "r"
    let lamDef last goodPath = lamCaseE $ (match (tupP [varP builder, tupP [varP var, if last then varP rest else infixP (litP $ CharL '/') n_infix (varP rest)]])
                                                 (normalB goodPath)
                                                 []):(if last then [] else [match wildP (normalB $ listE []) []])
        lamDef' = lamDef False
        mapper applyVar = appE (appE (appE f_flip f_concatMap) (appE (appE f_map (lamE [varP x] (tupE [if applyVar then appE (varE builder) (varE var) else varE builder, varE x]))) (appE (appE f_readsPrec $ varE depth) $ varE rest)))
        createIteration [] [] = (lamDef True) (listE [tupE [appE (varE builder) (varE var), (varE rest)]])
        createIteration [] optionals@((_,options):opt') = lamDef True
                                                          (listE [appE (createIteration options opt') $ tupE [varE builder, tupE [varE var, varE rest]], useDefaults optionals])
        createIteration (req:moreReq) opt = lamDef' $ (mapper True) $ createIteration moreReq opt
        useDefaults ((category, options):restOptions) = let (toBuilder, [(lastMetricName, _ , ((firstOptionOfLastMectric, _):_))]) = splitAt (length options - 1) options
                                                            newBuilder = foldr (\(metricName, _, ((firstOptionName, _):_)) state -> appE state (conE $ toName $ category ++ metricName ++ firstOptionName)) (appE (varE builder) $ varE var) toBuilder
                                                            newVar = conE $ toName $ category ++ lastMetricName ++ firstOptionOfLastMectric
                                                         in appE (createIteration [] restOptions) $ tupE [newBuilder, tupE [newVar, varE rest]]
        createFirstIteration (_:req) opt = foldr (\_ state -> appE f_concat state) ((mapper False) $ createIteration req opt) opt
    instanceD
      (return [])
      (appT (conT $ mkName "Read") $ conT $ toName topName)
      [funD (mkName "readsPrec")
            [clause [varP depth, varP rest]
                    (normalB $ createFirstIteration types optionalTypes)
                    [funD builder [clause [] (normalB $ conE $ toName topName) []]]]]
                    -- This should create a recursive call. Everytime there is an optional route, it should forge to a path where it is not optional and a path where it has default values. See code above.

  return $ (createTopType:createSubTypes)
        ++ (deriveShowTop:deriveShowSubs)
        ++ (deriveReadTop:deriveReadSubs)

