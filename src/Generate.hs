{-# LANGUAGE DeriveDataTypeable #-}
module Main where

import Control.Monad
import Data.Word
import Numeric(readHex)
import qualified Data.ByteString as BS

import System.Console.CmdArgs
import Data.List.Split(splitOn)
import Network.Pcap

data Opts = Opts { oiface :: String
                 , ofromEthAddx :: String
                 , otoEthAddx :: String
                 , onumPkts :: Int
                 , opayloadLen :: Int
                 } deriving (Show, Data, Typeable)

opts = Opts { oiface       = "enp7s0"            &= name "iface"
            , ofromEthAddx = "00:11:22:33:44:55" &= name "from"
            , otoEthAddx   = "66:77:88:99:aa:bb" &= name "to"
            , onumPkts     = 1                   &= name "numpkts"
            , opayloadLen  = 16                  &= name "payloadlen"
            }

parseEthAddx :: String -> [Word8]
parseEthAddx addx
  | v@[a1,a2,a3,a4,a5,a6] <- splitOn ":" addx
  = map (fst . head . readHex) v
  | otherwise = error $ "Cannot parse addx:" ++ addx

main = do
  opt <- cmdArgs opts
  let iface = oiface opt
      numPkts = onumPkts opt
      fromAddx = parseEthAddx (ofromEthAddx opt)
      toAddx = parseEthAddx (otoEthAddx opt)
      pktType :: [Word8]
      pktType = map (fst . head . readHex) ["08", "00"]
      pktHdr = BS.pack $ toAddx ++ fromAddx ++ pktType
  putStrLn $ "Sending " ++ show numPkts ++ " pkts on " ++ iface ++ " from " ++ (ofromEthAddx opt) ++ " to " ++ (otoEthAddx opt)
  putStrLn $ "Header:" ++ show pktHdr ++ ", len:" ++ show (BS.length pktHdr)
  let payloadLen = opayloadLen opt
      mkPayload i = BS.pack $ replicate payloadLen (fromIntegral i :: Word8)
  poutf <- openLive iface 32 False 0
  forM_ [1..numPkts] $ \i -> do
    let outPkt = pktHdr `BS.append` (mkPayload i)
    putStrLn $ "Sending pkt " ++ show i
    putStrLn $ "Pkt:" ++ show outPkt ++ ", len:" ++ show (BS.length outPkt)
    sendPacketBS poutf outPkt
