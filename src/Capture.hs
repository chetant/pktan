{-# LANGUAGE DeriveDataTypeable #-}
module Main where

import Control.Monad
import Data.Word
import Numeric(showHex)
import qualified Data.ByteString as BS

import System.Console.CmdArgs
import Data.List.Split(splitOn)
import Network.Pcap

data Opts = Opts { oiface :: String
                 } deriving (Show, Data, Typeable)

opts = Opts { oiface = "enp7s0" &= name "iface"
            }

hexPrint = concat . map (flip showHex "") . BS.unpack

main = do
  opt <- cmdArgs opts
  let iface = oiface opt
  putStrLn $ "Listening on " ++ iface
  pinf <- openLive iface 65535 True 0
  let cb pktHdr payload = do
        let (toAddx, res) = BS.splitAt 6 payload
            (fromAddx, payload') = BS.splitAt 6 res
        putStrLn $ "From:" ++ hexPrint fromAddx ++ " To:" ++ hexPrint toAddx
        print $ hexPrint payload'
  loopBS pinf (-1) cb
