----------------------------------------------------------------------
----																					----
---- Basic DES Block Cypher IP Core											----
---- 																					----
---- Implementation of DES-56 ECB mode IP core.							----
---- 																					----
---- To Do: 																		----
---- - 																				----
---- 																					----
---- Author(s): 																	----
---- - Steven R. McQueen, srmcqueen@opencores.org 						----
---- 																					----
----------------------------------------------------------------------
---- 																					----
---- Copyright (C) 2003 Steven R. McQueen									----
---- 																					----
---- This source file may be used and distributed without 			----
---- restriction provided that this copyright statement is not 	----
---- removed from the file and that any derivative work contains 	----
---- the original copyright notice and the associated disclaimer. ----
---- 																					----
---- This source file is free software; you can redistribute it 	----
---- and/or modify it under the terms of the GNU Lesser General 	----
---- Public License as published by the Free Software Foundation; ----
---- either version 2.1 of the License, or (at your option) any 	----
---- later version. 																----
---- 																					----
---- This source is distributed in the hope that it will be 		----
---- useful, but WITHOUT ANY WARRANTY; without even the implied 	----
---- warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR 		----
---- PURPOSE. See the GNU Lesser General Public License for more 	----
---- details. 																		----
---- 																					----
---- You should have received a copy of the GNU Lesser General 	----
---- Public License along with this source; if not, download it 	----
---- from http://www.opencores.org/lgpl.shtml 							----
---- 																					----
----------------------------------------------------------------------
--
-- CVS Revision History
--
-- $Log: not supported by cvs2svn $
--

-- This module implements the DES 56-bit Key Block Cypher. It expects to receive the 64-bit
-- data block to be encrypted or decrypted on the indata bus, and the 64-bit key on the inKey
-- bus. When the DS signal is high, encryption/decryption begins.	If the DECIPHER signal is
-- low when the DS signal is raised, the operation will be encryption. If the DECIPHER signal
-- is high when the DS signal goes high, the operation will be decryption. With each clock 
-- cycle, one round of encryption is performed.	After 16 rounds, the resulting message block
-- is presented on the OUTDATA bus and the RDY signal is set high.
--
-- Comments, questions and suggestions may be directed to the author at srmcqueen@mcqueentech.com.


library IEEE;
use IEEE.STD_LOGIC_1164.ALL;
use IEEE.STD_LOGIC_ARITH.ALL;
use IEEE.STD_LOGIC_UNSIGNED.ALL;

--  Uncomment the following lines to use the declarations that are
--  provided for instantiating Xilinx primitive components.
--library UNISIM;
--use UNISIM.VComponents.all;

entity des56 is
    Port ( indata : in std_logic_vector(0 to 63);
           inkey : in std_logic_vector(0 to 63);
           outdata : out std_logic_vector(0 to 63);
			  decipher: in std_logic;
           ds : in std_logic;
           clk : in std_logic;
			  rst : in std_logic;
           rdy : out std_logic);
end des56;

architecture des of des56 is
--attribute keep: string;
--attribute nodelay: string;
--attribute s: string;

--attribute nodelay of indata: signal is "true";
--attribute nodelay of inkey: signal is "true";
--attribute nodelay of decipher: signal is "true";
--attribute nodelay of ds: signal is "true";
--attribute nodelay of clk: signal is "true";
--attribute nodelay of rst: signal is "true";
--attribute nodelay of rdy: signal is "true";
--attribute nodelay of outdata: signal is "true";

--attribute s of indata: signal is "yes";
--attribute s of inkey: signal is "yes";
--attribute s of decipher: signal is "yes";
--attribute s of ds: signal is "yes";
--attribute s of clk: signal is "yes";
--attribute s of rst: signal is "yes";
--attribute s of rdy: signal is "yes";
--attribute s of outdata: signal is "yes";

--signal xclk: std_logic;
--attribute keep of xclk: signal is "true";

-- These signals hold the round keys - they are loaded on the first clock
signal  K01: std_logic_vector(0 to 47); 
signal  K02: std_logic_vector(0 to 47); 
signal  K03: std_logic_vector(0 to 47); 
signal  K04: std_logic_vector(0 to 47); 
signal  K05: std_logic_vector(0 to 47); 
signal  K06: std_logic_vector(0 to 47); 
signal  K07: std_logic_vector(0 to 47); 
signal  K08: std_logic_vector(0 to 47); 
signal  K09: std_logic_vector(0 to 47); 
signal  K10: std_logic_vector(0 to 47); 
signal  K11: std_logic_vector(0 to 47); 
signal  K12: std_logic_vector(0 to 47); 
signal  K13: std_logic_vector(0 to 47); 
signal  K14: std_logic_vector(0 to 47); 
signal  K15: std_logic_vector(0 to 47); 

-- mykey and inmsg are inputs to the encryption round logic
-- they will get new values on each clock
-- outmsg is the result of the encryption round, it will become inmsg for the next round
-- there are 16 encryption rounds in DES
signal mykey: std_logic_vector(0 to 47); 
--attribute keep of mykey: signal is "true";
signal inmsg: std_logic_vector(0 to 63);
--attribute keep of inmsg: signal is "true";
signal outmsg: std_logic_vector(0 to 63);
--attribute keep of outmsg: signal is "true";

-- round counters. countup is used for encryption, countdown is for decryption
-- mycounter takes its value from countup or countdown
signal countup: integer range 0 to 16;
signal countdown: integer range 0 to 16;
signal mycounter: integer range 0 to 16;
--attribute keep of mycounter: signal is "true";

-- the decrypt register holds the decrypt/encrypt switch
signal decrypt: std_logic;
signal ready: std_logic;

-- various work signals. I want most of them to be wires, but
-- they may be registers or latches, depending on the synthesizer
	signal d: std_logic_vector(0 to 47);
	signal f: std_logic_vector(0 to 31);
	signal b1: std_logic_vector(0 to 5);
	signal b2: std_logic_vector(0 to 5);
	signal b3: std_logic_vector(0 to 5);
	signal b4: std_logic_vector(0 to 5);
	signal b5: std_logic_vector(0 to 5);
	signal b6: std_logic_vector(0 to 5);
	signal b7: std_logic_vector(0 to 5);
	signal b8: std_logic_vector(0 to 5);
	signal s1: std_logic_vector(0 to 3);
	signal s2: std_logic_vector(0 to 3);
	signal s3: std_logic_vector(0 to 3);
	signal s4: std_logic_vector(0 to 3);
	signal s5: std_logic_vector(0 to 3);
	signal s6: std_logic_vector(0 to 3);
	signal s7: std_logic_vector(0 to 3);
	signal s8: std_logic_vector(0 to 3);



begin

-- Register Input Data
--
-- When data strobe is high and clock is on the rising edge,
-- load the round key registers.
	RegData: process (clk, ds, decipher)

	begin

		if rising_edge(clk) then
			if ds = '1' then
				if decipher = '1' then
					K15 <=
						inkey(9) & inkey(50) & inkey(33) & inkey(59) & inkey(48) & inkey(16) & inkey(32) & inkey(56) &
						inkey(1) & inkey(8) & inkey(18) & inkey(41) & inkey(2) & inkey(34) & inkey(25) & inkey(24) &
						inkey(43) & inkey(57) & inkey(58) & inkey(0) & inkey(35) & inkey(26) & inkey(17) & inkey(40) &
						inkey(21) & inkey(27) & inkey(38) & inkey(53) & inkey(36) & inkey(3) & inkey(46) & inkey(29) &
						inkey(4) & inkey(52) & inkey(22) & inkey(28) & inkey(60) & inkey(20) & inkey(37) & inkey(62) &
						inkey(14) & inkey(19) & inkey(44) & inkey(13) & inkey(12) & inkey(61) & inkey(54) & inkey(30);

					K14 <=
						inkey(1) & inkey(42) & inkey(25) & inkey(51) & inkey(40) & inkey(8) & inkey(24) & inkey(48) &
						inkey(58) & inkey(0) & inkey(10) & inkey(33) & inkey(59) & inkey(26) & inkey(17) & inkey(16) &
						inkey(35) & inkey(49) & inkey(50) & inkey(57) & inkey(56) & inkey(18) & inkey(9) & inkey(32) &
						inkey(13) & inkey(19) & inkey(30) & inkey(45) & inkey(28) & inkey(62) & inkey(38) & inkey(21) &
						inkey(27) & inkey(44) & inkey(14) & inkey(20) & inkey(52) & inkey(12) & inkey(29) & inkey(54) &
						inkey(6) & inkey(11) & inkey(36) & inkey(5) & inkey(4) & inkey(53) & inkey(46) & inkey(22);
		
					K13 <=
						inkey(50) & inkey(26) & inkey(9) & inkey(35) & inkey(24) & inkey(57) & inkey(8) & inkey(32) &
						inkey(42) & inkey(49) & inkey(59) & inkey(17) & inkey(43) & inkey(10) & inkey(1) & inkey(0) &
						inkey(48) & inkey(33) & inkey(34) & inkey(41) & inkey(40) & inkey(2) & inkey(58) & inkey(16) &
						inkey(60) & inkey(3) & inkey(14) & inkey(29) & inkey(12) & inkey(46) & inkey(22) & inkey(5) &
						inkey(11) & inkey(28) & inkey(61) & inkey(4) & inkey(36) & inkey(27) & inkey(13) & inkey(38) &
						inkey(53) & inkey(62) & inkey(20) & inkey(52) & inkey(19) & inkey(37) & inkey(30) & inkey(6);

					K12 <=	
						inkey(34) & inkey(10) & inkey(58) & inkey(48) & inkey(8) & inkey(41) & inkey(57) & inkey(16) &
	 					inkey(26) & inkey(33) & inkey(43) & inkey(1) & inkey(56) & inkey(59) & inkey(50) & inkey(49) &
						inkey(32) & inkey(17) & inkey(18) & inkey(25) & inkey(24) & inkey(51) & inkey(42) & inkey(0) &
						inkey(44) & inkey(54) & inkey(61) & inkey(13) & inkey(27) & inkey(30) & inkey(6) & inkey(52) &
						inkey(62) & inkey(12) & inkey(45) & inkey(19) & inkey(20) & inkey(11) & inkey(60) & inkey(22) &
						inkey(37) & inkey(46) & inkey(4) & inkey(36) & inkey(3) & inkey(21) & inkey(14) & inkey(53);

					K11 <=	
						inkey(18) & inkey(59) & inkey(42) & inkey(32) & inkey(57) & inkey(25) & inkey(41) & inkey(0) &
						inkey(10) & inkey(17) & inkey(56) & inkey(50) & inkey(40) & inkey(43) & inkey(34) & inkey(33) &
						inkey(16) & inkey(1) & inkey(2) & inkey(9) & inkey(8) & inkey(35) & inkey(26) & inkey(49) &
						inkey(28) & inkey(38) & inkey(45) & inkey(60) & inkey(11) & inkey(14) & inkey(53) & inkey(36) &
						inkey(46) & inkey(27) & inkey(29) & inkey(3) & inkey(4) & inkey(62) & inkey(44) & inkey(6) &
						inkey(21) & inkey(30) & inkey(19) & inkey(20) & inkey(54) & inkey(5) & inkey(61) & inkey(37);

					K10 <=	
						inkey(2) & inkey(43) & inkey(26) & inkey(16) & inkey(41) & inkey(9) & inkey(25) & inkey(49) &
						inkey(59) & inkey(1) & inkey(40) & inkey(34) & inkey(24) & inkey(56) & inkey(18) & inkey(17) &
						inkey(0) & inkey(50) & inkey(51) & inkey(58) & inkey(57) & inkey(48) & inkey(10) & inkey(33) &
						inkey(12) & inkey(22) & inkey(29) & inkey(44) & inkey(62) & inkey(61) & inkey(37) & inkey(20) &
						inkey(30) & inkey(11) & inkey(13) & inkey(54) & inkey(19) & inkey(46) & inkey(28) & inkey(53) &
						inkey(5) & inkey(14) & inkey(3) & inkey(4) & inkey(38) & inkey(52) & inkey(45) & inkey(21);

					K09 <=	
						inkey(51) & inkey(56) & inkey(10) & inkey(0) & inkey(25) & inkey(58) & inkey(9) & inkey(33) &
						inkey(43) & inkey(50) & inkey(24) & inkey(18) & inkey(8) & inkey(40) & inkey(2) & inkey(1) &
						inkey(49) & inkey(34) & inkey(35) & inkey(42) & inkey(41) & inkey(32) & inkey(59) & inkey(17) &
						inkey(27) & inkey(6) & inkey(13) & inkey(28) & inkey(46) & inkey(45) & inkey(21) & inkey(4) &
						inkey(14) & inkey(62) & inkey(60) & inkey(38) & inkey(3) & inkey(30) & inkey(12) & inkey(37) &
						inkey(52) & inkey(61) & inkey(54) & inkey(19) & inkey(22) & inkey(36) & inkey(29) & inkey(5);

					K08 <=	
						inkey(35) & inkey(40) & inkey(59) & inkey(49) & inkey(9) & inkey(42) & inkey(58) & inkey(17) &
						inkey(56) & inkey(34) & inkey(8) & inkey(2) & inkey(57) & inkey(24) & inkey(51) & inkey(50) &
						inkey(33) & inkey(18) & inkey(48) & inkey(26) & inkey(25) & inkey(16) & inkey(43) & inkey(1) &
						inkey(11) & inkey(53) & inkey(60) & inkey(12) & inkey(30) & inkey(29) & inkey(5) & inkey(19) &
						inkey(61) & inkey(46) & inkey(44) & inkey(22) & inkey(54) & inkey(14) & inkey(27) & inkey(21) &
						inkey(36) & inkey(45) & inkey(38) & inkey(3) & inkey(6) & inkey(20) & inkey(13) & inkey(52);

					K07 <=	
						inkey(56) & inkey(32) & inkey(51) & inkey(41) & inkey(1) & inkey(34) & inkey(50) & inkey(9) &
						inkey(48) & inkey(26) & inkey(0) & inkey(59) & inkey(49) & inkey(16) & inkey(43) & inkey(42) &
						inkey(25) & inkey(10) & inkey(40) & inkey(18) & inkey(17) & inkey(8) & inkey(35) & inkey(58) &
						inkey(3) & inkey(45) & inkey(52) & inkey(4) & inkey(22) & inkey(21) & inkey(60) & inkey(11) &
						inkey(53) & inkey(38) & inkey(36) & inkey(14) & inkey(46) & inkey(6) & inkey(19) & inkey(13) &
						inkey(28) & inkey(37) & inkey(30) & inkey(62) & inkey(61) & inkey(12) & inkey(5) & inkey(44);
			
					K06 <=	
						inkey(40) & inkey(16) & inkey(35) & inkey(25) & inkey(50) & inkey(18) & inkey(34) & inkey(58) &
						inkey(32) & inkey(10) & inkey(49) & inkey(43) & inkey(33) & inkey(0) & inkey(56) & inkey(26) &
						inkey(9) & inkey(59) & inkey(24) & inkey(2) & inkey(1) & inkey(57) & inkey(48) & inkey(42) &
						inkey(54) & inkey(29) & inkey(36) & inkey(19) & inkey(6) & inkey(5) & inkey(44) & inkey(62) &
						inkey(37) & inkey(22) & inkey(20) & inkey(61) & inkey(30) & inkey(53) & inkey(3) & inkey(60) &
						inkey(12) & inkey(21) & inkey(14) & inkey(46) & inkey(45) & inkey(27) & inkey(52) & inkey(28);

					K05 <=	
						inkey(24) & inkey(0) & inkey(48) & inkey(9) & inkey(34) & inkey(2) & inkey(18) & inkey(42) &
						inkey(16) & inkey(59) & inkey(33) & inkey(56) & inkey(17) & inkey(49) & inkey(40) & inkey(10) &
						inkey(58) & inkey(43) & inkey(8) & inkey(51) & inkey(50) & inkey(41) & inkey(32) & inkey(26) &
						inkey(38) & inkey(13) & inkey(20) & inkey(3) & inkey(53) & inkey(52) & inkey(28) & inkey(46) &
						inkey(21) & inkey(6) & inkey(4) & inkey(45) & inkey(14) & inkey(37) & inkey(54) & inkey(44) &
						inkey(27) & inkey(5) & inkey(61) & inkey(30) & inkey(29) & inkey(11) & inkey(36) & inkey(12);

					K04 <=	
						inkey(8) & inkey(49) & inkey(32) & inkey(58) & inkey(18) & inkey(51) & inkey(2) & inkey(26) &
						inkey(0) & inkey(43) & inkey(17) & inkey(40) & inkey(1) & inkey(33) & inkey(24) & inkey(59) &
						inkey(42) & inkey(56) & inkey(57) & inkey(35) & inkey(34) & inkey(25) & inkey(16) & inkey(10) &
						inkey(22) & inkey(60) & inkey(4) & inkey(54) & inkey(37) & inkey(36) & inkey(12) & inkey(30) &
						inkey(5) & inkey(53) & inkey(19) & inkey(29) & inkey(61) & inkey(21) & inkey(38) & inkey(28) &
						inkey(11) & inkey(52) & inkey(45) & inkey(14) & inkey(13) & inkey(62) & inkey(20) & inkey(27);

					K03 <=	
						inkey(57) & inkey(33) & inkey(16) & inkey(42) & inkey(2) & inkey(35) & inkey(51) & inkey(10) &
						inkey(49) & inkey(56) & inkey(1) & inkey(24) & inkey(50) & inkey(17) & inkey(8) & inkey(43) &
						inkey(26) & inkey(40) & inkey(41) & inkey(48) & inkey(18) & inkey(9) & inkey(0) & inkey(59) &
						inkey(6) & inkey(44) & inkey(19) & inkey(38) & inkey(21) & inkey(20) & inkey(27) & inkey(14) &
						inkey(52) & inkey(37) & inkey(3) & inkey(13) & inkey(45) & inkey(5) & inkey(22) & inkey(12) &
						inkey(62) & inkey(36) & inkey(29) & inkey(61) & inkey(60) & inkey(46) & inkey(4) & inkey(11);

					K02 <=	
						inkey(41) & inkey(17) & inkey(0) & inkey(26) & inkey(51) & inkey(48) & inkey(35) & inkey(59) &
						inkey(33) & inkey(40) & inkey(50) & inkey(8) & inkey(34) & inkey(1) & inkey(57) & inkey(56) &
						inkey(10) & inkey(24) & inkey(25) & inkey(32) & inkey(2) & inkey(58) & inkey(49) & inkey(43) &
						inkey(53) & inkey(28) & inkey(3) & inkey(22) & inkey(5) & inkey(4) & inkey(11) & inkey(61) &
						inkey(36) & inkey(21) & inkey(54) & inkey(60) & inkey(29) & inkey(52) & inkey(6) & inkey(27) &
						inkey(46) & inkey(20) & inkey(13) & inkey(45) & inkey(44) & inkey(30) & inkey(19) & inkey(62);

					K01 <=	
						inkey(25) & inkey(1) & inkey(49) & inkey(10) & inkey(35) & inkey(32) & inkey(48) & inkey(43) &
						inkey(17) & inkey(24) & inkey(34) & inkey(57) & inkey(18) & inkey(50) & inkey(41) & inkey(40) &
						inkey(59) & inkey(8) & inkey(9) & inkey(16) & inkey(51) & inkey(42) & inkey(33) & inkey(56) &
						inkey(37) & inkey(12) & inkey(54) & inkey(6) & inkey(52) & inkey(19) & inkey(62) & inkey(45) &
						inkey(20) & inkey(5) & inkey(38) & inkey(44) & inkey(13) & inkey(36) & inkey(53) & inkey(11) &
						inkey(30) & inkey(4) & inkey(60) & inkey(29) & inkey(28) & inkey(14) & inkey(3) & inkey(46);

				else

					K01 <=
						inkey(1) & inkey(42) & inkey(25) & inkey(51) & inkey(40) & inkey(8) & inkey(24) & inkey(48) &
						inkey(58) & inkey(0) & inkey(10) & inkey(33) & inkey(59) & inkey(26) & inkey(17) & inkey(16) &
						inkey(35) & inkey(49) & inkey(50) & inkey(57) & inkey(56) & inkey(18) & inkey(9) & inkey(32) &
						inkey(13) & inkey(19) & inkey(30) & inkey(45) & inkey(28) & inkey(62) & inkey(38) & inkey(21) &
						inkey(27) & inkey(44) & inkey(14) & inkey(20) & inkey(52) & inkey(12) & inkey(29) & inkey(54) &
						inkey(6) & inkey(11) & inkey(36) & inkey(5) & inkey(4) & inkey(53) & inkey(46) & inkey(22);
		
					K02 <=
						inkey(50) & inkey(26) & inkey(9) & inkey(35) & inkey(24) & inkey(57) & inkey(8) & inkey(32) &
						inkey(42) & inkey(49) & inkey(59) & inkey(17) & inkey(43) & inkey(10) & inkey(1) & inkey(0) &
						inkey(48) & inkey(33) & inkey(34) & inkey(41) & inkey(40) & inkey(2) & inkey(58) & inkey(16) &
						inkey(60) & inkey(3) & inkey(14) & inkey(29) & inkey(12) & inkey(46) & inkey(22) & inkey(5) &
						inkey(11) & inkey(28) & inkey(61) & inkey(4) & inkey(36) & inkey(27) & inkey(13) & inkey(38) &
						inkey(53) & inkey(62) & inkey(20) & inkey(52) & inkey(19) & inkey(37) & inkey(30) & inkey(6);

					K03 <=	
						inkey(34) & inkey(10) & inkey(58) & inkey(48) & inkey(8) & inkey(41) & inkey(57) & inkey(16) &
	 					inkey(26) & inkey(33) & inkey(43) & inkey(1) & inkey(56) & inkey(59) & inkey(50) & inkey(49) &
						inkey(32) & inkey(17) & inkey(18) & inkey(25) & inkey(24) & inkey(51) & inkey(42) & inkey(0) &
						inkey(44) & inkey(54) & inkey(61) & inkey(13) & inkey(27) & inkey(30) & inkey(6) & inkey(52) &
						inkey(62) & inkey(12) & inkey(45) & inkey(19) & inkey(20) & inkey(11) & inkey(60) & inkey(22) &
						inkey(37) & inkey(46) & inkey(4) & inkey(36) & inkey(3) & inkey(21) & inkey(14) & inkey(53);

					K04 <=	
						inkey(18) & inkey(59) & inkey(42) & inkey(32) & inkey(57) & inkey(25) & inkey(41) & inkey(0) &
						inkey(10) & inkey(17) & inkey(56) & inkey(50) & inkey(40) & inkey(43) & inkey(34) & inkey(33) &
						inkey(16) & inkey(1) & inkey(2) & inkey(9) & inkey(8) & inkey(35) & inkey(26) & inkey(49) &
						inkey(28) & inkey(38) & inkey(45) & inkey(60) & inkey(11) & inkey(14) & inkey(53) & inkey(36) &
						inkey(46) & inkey(27) & inkey(29) & inkey(3) & inkey(4) & inkey(62) & inkey(44) & inkey(6) &
						inkey(21) & inkey(30) & inkey(19) & inkey(20) & inkey(54) & inkey(5) & inkey(61) & inkey(37);

					K05 <=	
						inkey(2) & inkey(43) & inkey(26) & inkey(16) & inkey(41) & inkey(9) & inkey(25) & inkey(49) &
						inkey(59) & inkey(1) & inkey(40) & inkey(34) & inkey(24) & inkey(56) & inkey(18) & inkey(17) &
						inkey(0) & inkey(50) & inkey(51) & inkey(58) & inkey(57) & inkey(48) & inkey(10) & inkey(33) &
						inkey(12) & inkey(22) & inkey(29) & inkey(44) & inkey(62) & inkey(61) & inkey(37) & inkey(20) &
						inkey(30) & inkey(11) & inkey(13) & inkey(54) & inkey(19) & inkey(46) & inkey(28) & inkey(53) &
						inkey(5) & inkey(14) & inkey(3) & inkey(4) & inkey(38) & inkey(52) & inkey(45) & inkey(21);

					K06 <=	
						inkey(51) & inkey(56) & inkey(10) & inkey(0) & inkey(25) & inkey(58) & inkey(9) & inkey(33) &
						inkey(43) & inkey(50) & inkey(24) & inkey(18) & inkey(8) & inkey(40) & inkey(2) & inkey(1) &
						inkey(49) & inkey(34) & inkey(35) & inkey(42) & inkey(41) & inkey(32) & inkey(59) & inkey(17) &
						inkey(27) & inkey(6) & inkey(13) & inkey(28) & inkey(46) & inkey(45) & inkey(21) & inkey(4) &
						inkey(14) & inkey(62) & inkey(60) & inkey(38) & inkey(3) & inkey(30) & inkey(12) & inkey(37) &
						inkey(52) & inkey(61) & inkey(54) & inkey(19) & inkey(22) & inkey(36) & inkey(29) & inkey(5);

					K07 <=	
						inkey(35) & inkey(40) & inkey(59) & inkey(49) & inkey(9) & inkey(42) & inkey(58) & inkey(17) &
						inkey(56) & inkey(34) & inkey(8) & inkey(2) & inkey(57) & inkey(24) & inkey(51) & inkey(50) &
						inkey(33) & inkey(18) & inkey(48) & inkey(26) & inkey(25) & inkey(16) & inkey(43) & inkey(1) &
						inkey(11) & inkey(53) & inkey(60) & inkey(12) & inkey(30) & inkey(29) & inkey(5) & inkey(19) &
						inkey(61) & inkey(46) & inkey(44) & inkey(22) & inkey(54) & inkey(14) & inkey(27) & inkey(21) &
						inkey(36) & inkey(45) & inkey(38) & inkey(3) & inkey(6) & inkey(20) & inkey(13) & inkey(52);

					K08 <=	
						inkey(56) & inkey(32) & inkey(51) & inkey(41) & inkey(1) & inkey(34) & inkey(50) & inkey(9) &
						inkey(48) & inkey(26) & inkey(0) & inkey(59) & inkey(49) & inkey(16) & inkey(43) & inkey(42) &
						inkey(25) & inkey(10) & inkey(40) & inkey(18) & inkey(17) & inkey(8) & inkey(35) & inkey(58) &
						inkey(3) & inkey(45) & inkey(52) & inkey(4) & inkey(22) & inkey(21) & inkey(60) & inkey(11) &
						inkey(53) & inkey(38) & inkey(36) & inkey(14) & inkey(46) & inkey(6) & inkey(19) & inkey(13) &
						inkey(28) & inkey(37) & inkey(30) & inkey(62) & inkey(61) & inkey(12) & inkey(5) & inkey(44);
			
					K09 <=	
						inkey(40) & inkey(16) & inkey(35) & inkey(25) & inkey(50) & inkey(18) & inkey(34) & inkey(58) &
						inkey(32) & inkey(10) & inkey(49) & inkey(43) & inkey(33) & inkey(0) & inkey(56) & inkey(26) &
						inkey(9) & inkey(59) & inkey(24) & inkey(2) & inkey(1) & inkey(57) & inkey(48) & inkey(42) &
						inkey(54) & inkey(29) & inkey(36) & inkey(19) & inkey(6) & inkey(5) & inkey(44) & inkey(62) &
						inkey(37) & inkey(22) & inkey(20) & inkey(61) & inkey(30) & inkey(53) & inkey(3) & inkey(60) &
						inkey(12) & inkey(21) & inkey(14) & inkey(46) & inkey(45) & inkey(27) & inkey(52) & inkey(28);

					K10 <=	
						inkey(24) & inkey(0) & inkey(48) & inkey(9) & inkey(34) & inkey(2) & inkey(18) & inkey(42) &
						inkey(16) & inkey(59) & inkey(33) & inkey(56) & inkey(17) & inkey(49) & inkey(40) & inkey(10) &
						inkey(58) & inkey(43) & inkey(8) & inkey(51) & inkey(50) & inkey(41) & inkey(32) & inkey(26) &
						inkey(38) & inkey(13) & inkey(20) & inkey(3) & inkey(53) & inkey(52) & inkey(28) & inkey(46) &
						inkey(21) & inkey(6) & inkey(4) & inkey(45) & inkey(14) & inkey(37) & inkey(54) & inkey(44) &
						inkey(27) & inkey(5) & inkey(61) & inkey(30) & inkey(29) & inkey(11) & inkey(36) & inkey(12);

					K11 <=	
						inkey(8) & inkey(49) & inkey(32) & inkey(58) & inkey(18) & inkey(51) & inkey(2) & inkey(26) &
						inkey(0) & inkey(43) & inkey(17) & inkey(40) & inkey(1) & inkey(33) & inkey(24) & inkey(59) &
						inkey(42) & inkey(56) & inkey(57) & inkey(35) & inkey(34) & inkey(25) & inkey(16) & inkey(10) &
						inkey(22) & inkey(60) & inkey(4) & inkey(54) & inkey(37) & inkey(36) & inkey(12) & inkey(30) &
						inkey(5) & inkey(53) & inkey(19) & inkey(29) & inkey(61) & inkey(21) & inkey(38) & inkey(28) &
						inkey(11) & inkey(52) & inkey(45) & inkey(14) & inkey(13) & inkey(62) & inkey(20) & inkey(27);

					K12 <=	
						inkey(57) & inkey(33) & inkey(16) & inkey(42) & inkey(2) & inkey(35) & inkey(51) & inkey(10) &
						inkey(49) & inkey(56) & inkey(1) & inkey(24) & inkey(50) & inkey(17) & inkey(8) & inkey(43) &
						inkey(26) & inkey(40) & inkey(41) & inkey(48) & inkey(18) & inkey(9) & inkey(0) & inkey(59) &
						inkey(6) & inkey(44) & inkey(19) & inkey(38) & inkey(21) & inkey(20) & inkey(27) & inkey(14) &
						inkey(52) & inkey(37) & inkey(3) & inkey(13) & inkey(45) & inkey(5) & inkey(22) & inkey(12) &
						inkey(62) & inkey(36) & inkey(29) & inkey(61) & inkey(60) & inkey(46) & inkey(4) & inkey(11);

					K13 <=	
						inkey(41) & inkey(17) & inkey(0) & inkey(26) & inkey(51) & inkey(48) & inkey(35) & inkey(59) &
						inkey(33) & inkey(40) & inkey(50) & inkey(8) & inkey(34) & inkey(1) & inkey(57) & inkey(56) &
						inkey(10) & inkey(24) & inkey(25) & inkey(32) & inkey(2) & inkey(58) & inkey(49) & inkey(43) &
						inkey(53) & inkey(28) & inkey(3) & inkey(22) & inkey(5) & inkey(4) & inkey(11) & inkey(61) &
						inkey(36) & inkey(21) & inkey(54) & inkey(60) & inkey(29) & inkey(52) & inkey(6) & inkey(27) &
						inkey(46) & inkey(20) & inkey(13) & inkey(45) & inkey(44) & inkey(30) & inkey(19) & inkey(62);

					K14 <=	
						inkey(25) & inkey(1) & inkey(49) & inkey(10) & inkey(35) & inkey(32) & inkey(48) & inkey(43) &
						inkey(17) & inkey(24) & inkey(34) & inkey(57) & inkey(18) & inkey(50) & inkey(41) & inkey(40) &
						inkey(59) & inkey(8) & inkey(9) & inkey(16) & inkey(51) & inkey(42) & inkey(33) & inkey(56) &
						inkey(37) & inkey(12) & inkey(54) & inkey(6) & inkey(52) & inkey(19) & inkey(62) & inkey(45) &
						inkey(20) & inkey(5) & inkey(38) & inkey(44) & inkey(13) & inkey(36) & inkey(53) & inkey(11) &
						inkey(30) & inkey(4) & inkey(60) & inkey(29) & inkey(28) & inkey(14) & inkey(3) & inkey(46);

					K15 <=	
						inkey(17) & inkey(58) & inkey(41) & inkey(2) & inkey(56) & inkey(24) & inkey(40) & inkey(35) &
						inkey(9) & inkey(16) & inkey(26) & inkey(49) & inkey(10) & inkey(42) & inkey(33) & inkey(32) &
						inkey(51) & inkey(0) & inkey(1) & inkey(8) & inkey(43) & inkey(34) & inkey(25) & inkey(48) &
						inkey(29) & inkey(4) & inkey(46) & inkey(61) & inkey(44) & inkey(11) & inkey(54) & inkey(37) &
						inkey(12) & inkey(60) &  inkey(30) & inkey(36) & inkey(5) & inkey(28) & inkey(45) & inkey(3) &
						inkey(22) & inkey(27) & inkey(52) & inkey(21) & inkey(20) & inkey(6) & inkey(62) & inkey(38);
				end if;
			end if;
		end if;
	end process RegData;


-- Select the key value for the next encryption round
--  Use the current value of COUNTUP to determine which round of encryption is next.
--  Load the MYKEY register with the appropriate round key value.
--  Note that on the first pass, the round key is not available, and must be
--		loaded directly from the input signals. The correct value is determined by
--		the state of the DECIPHER signal.
	SetKey: process (clk, countup, decipher)	
	-- NOTE: according to ModelSim, the output value of some of these multiplexers
	--		is not stable for enough time before the clock is propagated. What can I do
	--    about that?
	begin
		if rising_edge(clk) then
			case countup is
				when 0 =>
					if decipher = '1' then
						mykey <=	
							inkey(17) & inkey(58) & inkey(41) & inkey(2) & inkey(56) & inkey(24) & inkey(40) & inkey(35) &
							inkey(9) & inkey(16) & inkey(26) & inkey(49) & inkey(10) & inkey(42) & inkey(33) & inkey(32) &
							inkey(51) & inkey(0) & inkey(1) & inkey(8) & inkey(43) & inkey(34) & inkey(25) & inkey(48) &
							inkey(29) & inkey(4) & inkey(46) & inkey(61) & inkey(44) & inkey(11) & inkey(54) & inkey(37) &
							inkey(12) & inkey(60) &  inkey(30) & inkey(36) & inkey(5) & inkey(28) & inkey(45) & inkey(3) &
							inkey(22) & inkey(27) & inkey(52) & inkey(21) & inkey(20) & inkey(6) & inkey(62) & inkey(38);
					else
						mykey <=
							inkey(9) & inkey(50) & inkey(33) & inkey(59) & inkey(48) & inkey(16) & inkey(32) & inkey(56) &
							inkey(1) & inkey(8) & inkey(18) & inkey(41) & inkey(2) & inkey(34) & inkey(25) & inkey(24) &
							inkey(43) & inkey(57) & inkey(58) & inkey(0) & inkey(35) & inkey(26) & inkey(17) & inkey(40) &
							inkey(21) & inkey(27) & inkey(38) & inkey(53) & inkey(36) & inkey(3) & inkey(46) & inkey(29) &
							inkey(4) & inkey(52) & inkey(22) & inkey(28) & inkey(60) & inkey(20) & inkey(37) & inkey(62) &
							inkey(14) & inkey(19) & inkey(44) & inkey(13) & inkey(12) & inkey(61) & inkey(54) & inkey(30);
					end if;
				when 1 =>
					mykey <= K01;
				when 2 =>
					mykey <= K02;
				when 3 =>
					mykey <= K03;
				when 4 =>
					mykey <= K04;
				when 5 =>
					mykey <= K05;
				when 6 =>
					mykey <= K06;
				when 7 =>
					mykey <= K07;
				when 8 =>
					mykey <= K08;
				when 9 =>
					mykey <= K09;
				when 10 =>
					mykey <= K10;
				when 11 =>
					mykey <= K11;
				when 12 =>
					mykey <= K12;
				when 13 =>
					mykey <= K13;
				when 14 =>
					mykey <= K14;
				when 15 =>
					mykey <= K15;
				when others =>
			end case;
		end if;

	end process SetKey;


-- Load the message word for the next encryption round
-- As in SetKey, the data must be taken from the input ports on the first round.
-- For all other rounds, the data value is taken from the OUTMSG signal. This signal
--		is produced by combinatorial logic.
--
--  The first round of this cycle can be the last round of the previous cycle. Output is
--		driven at this time.
	SetData: process (clk, countup, rst, ds)
		variable C17: std_logic_vector(1 to 64);
	begin
		if rst = '1' then
			rdy <= '1';
		elsif rising_edge(clk) then
			-- NOTE: INMSG is driven by a multiplexer. It seems that the output signal
			--		for this mux is not always stable before the clock is propagated. Same
			--		problem as above. Should I be using another construct?
			case countup is
				when 0 =>
					if ds = '1' then
						inmsg <= indata(57) & indata(49) & indata(41) & indata(33) & indata(25) & indata(17) & indata(9) & indata(1) &
							indata(59) & indata(51) & indata(43) & indata(35) & indata(27) & indata(19) & indata(11) & indata(3) &
							indata(61) & indata(53) & indata(45) & indata(37) & indata(29) & indata(21) & indata(13) & indata(5) &
							indata(63) & indata(55) & indata(47) & indata(39) & indata(31) & indata(23) & indata(15) & indata(7) &
							indata(56) & indata(48) & indata(40) & indata(32) & indata(24) & indata(16) & indata(8) & indata(0) &
							indata(58) & indata(50) & indata(42) & indata(34) & indata(26) & indata(18) & indata(10) & indata(2) &
							indata(60) & indata(52) & indata(44) & indata(36) & indata(28) & indata(20) & indata(12) & indata(4) &
							indata(62) & indata(54) & indata(46) & indata(38) & indata(30) & indata(22) & indata(14) & indata(6);
						rdy <= '0';		-- Manage the "Data ready" signal
					end if;
					if ready = '0' then		--ready is really a "crypto in progress" signal
						C17(1 to 32) := outmsg(32 to 63);
						C17(33 to 64) := outmsg(0 to 31);

						outdata <= C17(40) & C17(8) & C17(48) & C17(16) & C17(56) & C17(24) & C17(64) & C17(32) &
									  C17(39) & C17(7) & C17(47) & C17(15) & C17(55) & C17(23) & C17(63) & C17(31) &
									  C17(38) & C17(6) & C17(46) & C17(14) & C17(54) & C17(22) & C17(62) & C17(30) &
									  C17(37) & C17(5) & C17(45) & C17(13) & C17(53) & C17(21) & C17(61) & C17(29) &
									  C17(36) & C17(4) & C17(44) & C17(12) & C17(52) & C17(20) & C17(60) & C17(28) &
									  C17(35) & C17(3) & C17(43) & C17(11) & C17(51) & C17(19) & C17(59) & C17(27) & 
									  C17(34) & C17(2) & C17(42) & C17(10) & C17(50) & C17(18) & C17(58) & C17(26) &
									  C17(33) & C17(1) & C17(41) & C17(9) & C17(49) & C17(17) & C17(57) & C17(25);
						rdy <= '1';
					end if;
				when others =>
					inmsg <= outmsg;
					rdy <= '0';
			end case;
		end if;

	end process setdata;


-- This handles the READY signal and counts the counters
	Control: process (clk, ready, ds, RST, countup)
	
	begin

		if RST = '1' then
			ready <= '1';
			countup <= 0;

		elsif rising_edge(clk) then
			if ready = '1' then
				if ds = '1' then
					ready <= '0';
					countup <= 1;
				end if;
			else
				if countup = 0 then
					if ds = '0' then
						ready <= '1';
					end if;
				elsif countup < 15 then
					countup <= countup + 1;
				else
					countup <= 0;
				end if;
			end if;
		end if;

	end process control;


-- Combinatorial Logic
--   all of this takes around 7-8ns. Is there a way to make it faster?
--
-- expand 32 bits of the message word to 48 bits, mix it with the round key, 
-- then load it into 6-bit indexes.
	b1 <= (inmsg(63) & inmsg(36) & inmsg(32 to 35)) xor (mykey(0) & mykey(5) & mykey(1 to 4));
	b2 <= (inmsg(35) & inmsg(40) & inmsg(36 to 39)) xor (mykey(6) & mykey(11) & mykey(7 to 10));
	b3 <= (inmsg(39) & inmsg(44) & inmsg(40 to 43)) xor (mykey(12) & mykey(17) & mykey(13 to 16));
	b4 <= (inmsg(43) & inmsg(48) & inmsg(44 to 47)) xor (mykey(18) & mykey(23) & mykey(19 to 22));
	b5 <= (inmsg(47) & inmsg(52) & inmsg(48 to 51)) xor (mykey(24) & mykey(29) & mykey(25 to 28));
	b6 <= (inmsg(51) & inmsg(56) & inmsg(52 to 55)) xor (mykey(30) & mykey(35) & mykey(31 to 34));
	b7 <= (inmsg(55) & inmsg(60) & inmsg(56 to 59)) xor (mykey(36) & mykey(41) & mykey(37 to 40));
	b8 <= (inmsg(59) & inmsg(32) & inmsg(60 to 63)) xor (mykey(42) & mykey(47) & mykey(43 to 46));

-- 8 select statements to look up 4-bit S Box values based on the 6-bit indexes.
	with b1 select
		s1 <= x"e" when "000000",
				x"4" when "000001",
				x"d" when "000010",
				x"1" when "000011",
				x"2" when "000100",
				x"f" when "000101",
				x"b" when "000110",
				x"8" when "000111",
				x"3" when "001000",
				x"a" when "001001",
				x"6" when "001010",
				x"c" when "001011",
				x"5" when "001100",
				x"9" when "001101",
				x"0" when "001110",
				x"7" when "001111",
				x"0" when "010000",
				x"f" when "010001",
				x"7" when "010010",
				x"4" when "010011",
				x"e" when "010100",
				x"2" when "010101",
				x"d" when "010110",
				x"1" when "010111",
				x"a" when "011000",
				x"6" when "011001",
				x"c" when "011010",
				x"b" when "011011",
				x"9" when "011100",
				x"5" when "011101",
				x"3" when "011110",
				x"8" when "011111",
				x"4" when "100000",
				x"1" when "100001",
				x"e" when "100010",
				x"8" when "100011",
				x"d" when "100100",
				x"6" when "100101",
				x"2" when "100110",
				x"b" when "100111",
				x"f" when "101000",
				x"c" when "101001",
				x"9" when "101010",
				x"7" when "101011",
				x"3" when "101100",
				x"a" when "101101",
				x"5" when "101110",
				x"0" when "101111",
				x"f" when "110000",
				x"c" when "110001",
				x"8" when "110010",
				x"2" when "110011",
				x"4" when "110100",
				x"9" when "110101",
				x"1" when "110110",
				x"7" when "110111",
				x"5" when "111000",
				x"b" when "111001",
				x"3" when "111010",
				x"e" when "111011",
				x"a" when "111100",
				x"0" when "111101",
				x"6" when "111110",
				x"d" when "111111",
				"XXXX" when others;
				 

	with b2 select
		s2 <= x"f" when "000000",
				x"1" when "000001",
				x"8" when "000010",
				x"e" when "000011",
				x"6" when "000100",
				x"b" when "000101",
				x"3" when "000110",
				x"4" when "000111",
				x"9" when "001000",
				x"7" when "001001",
				x"2" when "001010",
				x"d" when "001011",
				x"c" when "001100",
				x"0" when "001101",
				x"5" when "001110",
				x"a" when "001111",
				x"3" when "010000",
				x"d" when "010001",
				x"4" when "010010",
				x"7" when "010011",
				x"f" when "010100",
				x"2" when "010101",
				x"8" when "010110",
				x"e" when "010111",
				x"c" when "011000",
				x"0" when "011001",
				x"1" when "011010",
				x"a" when "011011",
				x"6" when "011100",
				x"9" when "011101",
				x"b" when "011110",
				x"5" when "011111",
				x"0" when "100000",
				x"e" when "100001",
				x"7" when "100010",
				x"b" when "100011",
				x"a" when "100100",
				x"4" when "100101",
				x"d" when "100110",
				x"1" when "100111",
				x"5" when "101000",
				x"8" when "101001",
				x"c" when "101010",
				x"6" when "101011",
				x"9" when "101100",
				x"3" when "101101",
				x"2" when "101110",
				x"f" when "101111",
				x"d" when "110000",
				x"8" when "110001",
				x"a" when "110010",
				x"1" when "110011",
				x"3" when "110100",
				x"f" when "110101",
				x"4" when "110110",
				x"2" when "110111",
				x"b" when "111000",
				x"6" when "111001",
				x"7" when "111010",
				x"c" when "111011",
				x"0" when "111100",
				x"5" when "111101",
				x"e" when "111110",
				x"9" when "111111",
				"XXXX" when others;

	with b3 select
		s3 <= x"a" when "000000",
				x"0" when "000001",
				x"9" when "000010",
				x"e" when "000011",
				x"6" when "000100",
				x"3" when "000101",
				x"f" when "000110",
				x"5" when "000111",
				x"1" when "001000",
				x"d" when "001001",
				x"c" when "001010",
				x"7" when "001011",
				x"b" when "001100",
				x"4" when "001101",
				x"2" when "001110",
				x"8" when "001111",
				x"d" when "010000",
				x"7" when "010001",
				x"0" when "010010",
				x"9" when "010011",
				x"3" when "010100",
				x"4" when "010101",
				x"6" when "010110",
				x"a" when "010111",
				x"2" when "011000",
				x"8" when "011001",
				x"5" when "011010",
				x"e" when "011011",
				x"c" when "011100",
				x"b" when "011101",
				x"f" when "011110",
				x"1" when "011111",
				x"d" when "100000",
				x"6" when "100001",
				x"4" when "100010",
				x"9" when "100011",
				x"8" when "100100",
				x"f" when "100101",
				x"3" when "100110",
				x"0" when "100111",
				x"b" when "101000",
				x"1" when "101001",
				x"2" when "101010",
				x"c" when "101011",
				x"5" when "101100",
				x"a" when "101101",
				x"e" when "101110",
				x"7" when "101111",
				x"1" when "110000",
				x"a" when "110001",
				x"d" when "110010",
				x"0" when "110011",
				x"6" when "110100",
				x"9" when "110101",
				x"8" when "110110",
				x"7" when "110111",
				x"4" when "111000",
				x"f" when "111001",
				x"e" when "111010",
				x"3" when "111011",
				x"b" when "111100",
				x"5" when "111101",
				x"2" when "111110",
				x"c" when "111111",
				"XXXX" when others;

	with b4 select
		s4 <= x"7" when "000000",
				x"d" when "000001",
				x"e" when "000010",
				x"3" when "000011",
				x"0" when "000100",
				x"6" when "000101",
				x"9" when "000110",
				x"a" when "000111",
				x"1" when "001000",
				x"2" when "001001",
				x"8" when "001010",
				x"5" when "001011",
				x"b" when "001100",
				x"c" when "001101",
				x"4" when "001110",
				x"f" when "001111",
				x"d" when "010000",
				x"8" when "010001",
				x"b" when "010010",
				x"5" when "010011",
				x"6" when "010100",
				x"f" when "010101",
				x"0" when "010110",
				x"3" when "010111",
				x"4" when "011000",
				x"7" when "011001",
				x"2" when "011010",
				x"c" when "011011",
				x"1" when "011100",
				x"a" when "011101",
				x"e" when "011110",
				x"9" when "011111",
				x"a" when "100000",
				x"6" when "100001",
				x"9" when "100010",
				x"0" when "100011",
				x"c" when "100100",
				x"b" when "100101",
				x"7" when "100110",
				x"d" when "100111",
				x"f" when "101000",
				x"1" when "101001",
				x"3" when "101010",
				x"e" when "101011",
				x"5" when "101100",
				x"2" when "101101",
				x"8" when "101110",
				x"4" when "101111",
				x"3" when "110000",
				x"f" when "110001",
				x"0" when "110010",
				x"6" when "110011",
				x"a" when "110100",
				x"1" when "110101",
				x"d" when "110110",
				x"8" when "110111",
				x"9" when "111000",
				x"4" when "111001",
				x"5" when "111010",
				x"b" when "111011",
				x"c" when "111100",
				x"7" when "111101",
				x"2" when "111110",
				x"e" when "111111",
				"XXXX" when others;

	with b5 select
		s5 <= x"2" when "000000",
				x"c" when "000001",
				x"4" when "000010",
				x"1" when "000011",
				x"7" when "000100",
				x"a" when "000101",
				x"b" when "000110",
				x"6" when "000111",
				x"8" when "001000",
				x"5" when "001001",
				x"3" when "001010",
				x"f" when "001011",
				x"d" when "001100",
				x"0" when "001101",
				x"e" when "001110",
				x"9" when "001111",
				x"e" when "010000",
				x"b" when "010001",
				x"2" when "010010",
				x"c" when "010011",
				x"4" when "010100",
				x"7" when "010101",
				x"d" when "010110",
				x"1" when "010111",
				x"5" when "011000",
				x"0" when "011001",
				x"f" when "011010",
				x"a" when "011011",
				x"3" when "011100",
				x"9" when "011101",
				x"8" when "011110",
				x"6" when "011111",
				x"4" when "100000",
				x"2" when "100001",
				x"1" when "100010",
				x"b" when "100011",
				x"a" when "100100",
				x"d" when "100101",
				x"7" when "100110",
				x"8" when "100111",
				x"f" when "101000",
				x"9" when "101001",
				x"c" when "101010",
				x"5" when "101011",
				x"6" when "101100",
				x"3" when "101101",
				x"0" when "101110",
				x"e" when "101111",
				x"b" when "110000",
				x"8" when "110001",
				x"c" when "110010",
				x"7" when "110011",
				x"1" when "110100",
				x"e" when "110101",
				x"2" when "110110",
				x"d" when "110111",
				x"6" when "111000",
				x"f" when "111001",
				x"0" when "111010",
				x"9" when "111011",
				x"a" when "111100",
				x"4" when "111101",
				x"5" when "111110",
				x"3" when "111111",
				"XXXX" when others;

	with b6 select
		s6 <= x"c" when "000000",
				x"1" when "000001",
				x"a" when "000010",
				x"f" when "000011",
				x"9" when "000100",
				x"2" when "000101",
				x"6" when "000110",
				x"8" when "000111",
				x"0" when "001000",
				x"d" when "001001",
				x"3" when "001010",
				x"4" when "001011",
				x"e" when "001100",
				x"7" when "001101",
				x"5" when "001110",
				x"b" when "001111",
				x"a" when "010000",
				x"f" when "010001",
				x"4" when "010010",
				x"2" when "010011",
				x"7" when "010100",
				x"c" when "010101",
				x"9" when "010110",
				x"5" when "010111",
				x"6" when "011000",
				x"1" when "011001",
				x"d" when "011010",
				x"e" when "011011",
				x"0" when "011100",
				x"b" when "011101",
				x"3" when "011110",
				x"8" when "011111",
				x"9" when "100000",
				x"e" when "100001",
				x"f" when "100010",
				x"5" when "100011",
				x"2" when "100100",
				x"8" when "100101",
				x"c" when "100110",
				x"3" when "100111",
				x"7" when "101000",
				x"0" when "101001",
				x"4" when "101010",
				x"a" when "101011",
				x"1" when "101100",
				x"d" when "101101",
				x"b" when "101110",
				x"6" when "101111",
				x"4" when "110000",
				x"3" when "110001",
				x"2" when "110010",
				x"c" when "110011",
				x"9" when "110100",
				x"5" when "110101",
				x"f" when "110110",
				x"a" when "110111",
				x"b" when "111000",
				x"e" when "111001",
				x"1" when "111010",
				x"7" when "111011",
				x"6" when "111100",
				x"0" when "111101",
				x"8" when "111110",
				x"d" when "111111",
				"XXXX" when others;

	with b7 select
		s7 <= x"4" when "000000",
				x"b" when "000001",
				x"2" when "000010",
				x"e" when "000011",
				x"f" when "000100",
				x"0" when "000101",
				x"8" when "000110",
				x"d" when "000111",
				x"3" when "001000",
				x"c" when "001001",
				x"9" when "001010",
				x"7" when "001011",
				x"5" when "001100",
				x"a" when "001101",
				x"6" when "001110",
				x"1" when "001111",
				x"d" when "010000",
				x"0" when "010001",
				x"b" when "010010",
				x"7" when "010011",
				x"4" when "010100",
				x"9" when "010101",
				x"1" when "010110",
				x"a" when "010111",
				x"e" when "011000",
				x"3" when "011001",
				x"5" when "011010",
				x"c" when "011011",
				x"2" when "011100",
				x"f" when "011101",
				x"8" when "011110",
				x"6" when "011111",
				x"1" when "100000",
				x"4" when "100001",
				x"b" when "100010",
				x"d" when "100011",
				x"c" when "100100",
				x"3" when "100101",
				x"7" when "100110",
				x"e" when "100111",
				x"a" when "101000",
				x"f" when "101001",
				x"6" when "101010",
				x"8" when "101011",
				x"0" when "101100",
				x"5" when "101101",
				x"9" when "101110",
				x"2" when "101111",
				x"6" when "110000",
				x"b" when "110001",
				x"d" when "110010",
				x"8" when "110011",
				x"1" when "110100",
				x"4" when "110101",
				x"a" when "110110",
				x"7" when "110111",
				x"9" when "111000",
				x"5" when "111001",
				x"0" when "111010",
				x"f" when "111011",
				x"e" when "111100",
				x"2" when "111101",
				x"3" when "111110",
				x"c" when "111111",
				"XXXX" when others;

	with b8 select
		s8 <= x"d" when "000000",
				x"2" when "000001",
				x"8" when "000010",
				x"4" when "000011",
				x"6" when "000100",
				x"f" when "000101",
				x"b" when "000110",
				x"1" when "000111",
				x"a" when "001000",
				x"9" when "001001",
				x"3" when "001010",
				x"e" when "001011",
				x"5" when "001100",
				x"0" when "001101",
				x"c" when "001110",
				x"7" when "001111",
				x"1" when "010000",
				x"f" when "010001",
				x"d" when "010010",
				x"8" when "010011",
				x"a" when "010100",
				x"3" when "010101",
				x"7" when "010110",
				x"4" when "010111",
				x"c" when "011000",
				x"5" when "011001",
				x"6" when "011010",
				x"b" when "011011",
				x"0" when "011100",
				x"e" when "011101",
				x"9" when "011110",
				x"2" when "011111",
				x"7" when "100000",
				x"b" when "100001",
				x"4" when "100010",
				x"1" when "100011",
				x"9" when "100100",
				x"c" when "100101",
				x"e" when "100110",
				x"2" when "100111",
				x"0" when "101000",
				x"6" when "101001",
				x"a" when "101010",
				x"d" when "101011",
				x"f" when "101100",
				x"3" when "101101",
				x"5" when "101110",
				x"8" when "101111",
				x"2" when "110000",
				x"1" when "110001",
				x"e" when "110010",
				x"7" when "110011",
				x"4" when "110100",
				x"a" when "110101",
				x"8" when "110110",
				x"d" when "110111",
				x"f" when "111000",
				x"c" when "111001",
				x"9" when "111010",
				x"0" when "111011",
				x"3" when "111100",
				x"5" when "111101",
				x"6" when "111110",
				x"b" when "111111",
				"XXXX" when others;


-- Munge the S Boxes, then mix with the other 32 bits of the message word
	outmsg(32 to 63) <= (s4(3) & s2(2) & s5(3) & s6(0) & s8(0) & s3(3) & s7(3) & s5(0) &
								 s1(0) & s4(2) & s6(2) & s7(1) & s2(0) & s5(1) & s8(2) & s3(1) &
								 s1(1) & s2(3) & s6(3) & s4(1) & s8(3) & s7(2) & s1(2) & s3(0) &
								 s5(2) & s4(0) & s8(1) & s2(1) & s6(1) & s3(2) & s1(3) & s7(0)) xor inmsg(0 to 31);

-- the first 32 bits of the round output are the last 32 bits of the round input.
	outmsg(0 to 31) <= inmsg(32 to 63);

end des;
