module Main where

import Data.Cvss.V3
import System.Environment (getArgs, getProgName)
import System.Exit (exitWith, ExitCode(ExitFailure))

main :: IO ()
main = do
  args <- getArgs
  let showArgs = do
        progName <- getProgName
        putStrLn $ "Usage: " ++ progName ++ " cvss_vector"
        exitWith $ ExitFailure 1
  case args of
    [str] -> case filter (\(_, arr) -> null arr) $ reads str of
               [(cvss, [])] -> let [base, temp, env] = map (\x -> show $ fromRational $ x cvss) [calculateBaseScore, calculateTemporalScore, calculateEnvironmentalScore]
                                 in do putStrLn $ "Base score:          " ++ base
                                       putStrLn $ "Temporal score:      " ++ temp
                                       putStrLn $ "Environmental score: " ++ env
               _ -> do putStrLn $ "Could not decode vector " ++ str ++ "."
                       putStrLn "Make sure you use a vector that follows the specification, such as https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator"
                       showArgs
    _ -> showArgs
